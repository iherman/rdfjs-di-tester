// deno-lint-ignore-file require-await verbatim-module-syntax
import * as rdf     from '@rdfjs/types';
import { Command }  from 'commander';
import * as di      from 'rdfjs-di';
import * as process from 'node:process';
import * as path    from 'node:path';
import * as fs      from 'node:fs/promises';
import * as rdfn3   from './lib/rdfn3';
import * as n3      from 'n3';

interface JWKKeyPair {
    publicKey: JsonWebKey,
    privateKey: JsonWebKey,
    controller?: string,
    expires?: string
}

async function get_keys(keyref: string): Promise<di.KeyData[]> {
    const get_key = async (keyref: string): Promise<di.KeyData> => {
        const key_file: string = path.join(process.env.KEY_ENV ?? "", keyref) + '.json';
        const raw_keys: string = await fs.readFile(key_file, 'utf-8');
        const jwkKeyPair: JWKKeyPair = JSON.parse(raw_keys) as JWKKeyPair;
        return {
            publicKey  : await di.jwkToCrypto(jwkKeyPair.publicKey, false),
            privateKey : await di.jwkToCrypto(jwkKeyPair.privateKey, true),
            controller : jwkKeyPair?.controller,
            expires    : jwkKeyPair?.expires
        }
    };

    const refs: string[] = keyref.split(',').map((key: string): string => key.trim());
    const keyPromises = refs.map((key:string): Promise<di.KeyData> => get_key(key));
    return Promise.all(keyPromises);
}

(async (): Promise<void> => {
    const program = new Command();
    program
        .name('di_sign')
        .usage('[options] file')
        .description('Signing an RDF dataset or graph.')
        .option('-e, --embed', 'Create an embedded proof')
        .option('-a, --anchor <anchor>', 'Anchor for the proof graph(s). Must be a URL, possibly encoding the file name as a file URL. Only relevant for embedded proofs, otherwise ignored.')
        .option('-k, --key <keyref>', 'Key reference, or comma separated list thereof. Refers to file names in users key directory')
        .option('-g, --gid <gid>', 'Proof graph ID, or comma separated list thereof. Separates the proof graphs using these ID-s, or blank nodes. Must be URLs. This options is ignored in the embedded case')
        .option('-o, --output <output>', 'Output file')
        .parse(process.argv);

    const options = program.opts();

    const embed = options.embed ? true : false;
    const anchor: string | undefined = options.anchor;
    const output: string | undefined = options.output;
    const key_reference: string = options.key ?? 'eddsa';
    const graph_id_list: string[] = (options.gid ?? '').split(',').map((g:string): string => g.trim())

    if (program.args.length === 0) {
        console.log('No dataset reference')
    } else {
        const file_name = program.args[0];
        // Get the key
        const key_pairs: di.KeyData[] = await get_keys(key_reference);

        // Reconciliate, if necessary, the names of graph_id_urls, by adding bnodes to the end of the array if necessary
        const graph_names: string[] = ((): string[] => {
            if (key_pairs.length > graph_id_list.length) {
                // create a set of empty string, denoting blank nodes
                const bnodes: string[] = (new Array(key_pairs.length - graph_id_list.length)).fill('');
                return [...graph_id_list, ...bnodes];
            } else {
                return graph_id_list;
            }
        })();

        if (key_pairs.length === 0) {
            console.log('No valid key');
        } else {
            // Get the graph
            const dataset: rdf.DatasetCore = await rdfn3.get_quads(file_name);

            if (key_pairs.length === 1) {
                const proof: rdf.DatasetCore = await (async (): Promise<rdf.DatasetCore> => {
                    if (embed) {
                        return di.embedProofGraph(dataset, key_pairs[0], anchor ? rdfn3.DataFactory.namedNode(anchor) : undefined);
                    } else {
                        if (graph_id_list.length > 0 && graph_id_list[0] !== '') {
                            // the generated graph must be enclosed in a graph
                            const proofGraph = await di.generateProofGraph(dataset, key_pairs[0]);
                            const retval = new n3.Store();
                            const graphID: rdf.Quad_Graph = rdfn3.DataFactory.namedNode(graph_id_list[0]);
                            for (const q of proofGraph) {
                                retval.add(rdfn3.DataFactory.quad(q.subject, q.predicate, q.object, graphID));
                            }
                            return retval;
                        } else {
                            return di.generateProofGraph(dataset, key_pairs[0]);
                        }
                    }
                })();
                rdfn3.write_quads(proof, output);
            } else {
                const proof: rdf.DatasetCore = await (async (): Promise<rdf.DatasetCore> => {
                    if (embed) {
                        return di.embedProofGraph(dataset, key_pairs, anchor ? rdfn3.DataFactory.namedNode(anchor) : undefined);
                    } else {
                        const graphs: rdf.DatasetCore[] = await di.generateProofGraph(dataset, key_pairs);
                        // Each dataset core should be transformed into a named graph
                        const retval = new n3.Store();
                        for (let i: number = 0; i < graphs.length; i++) {
                            // Create a new dataset name:
                            const graphID: rdf.Quad_Graph = graph_names[i] === '' ? rdfn3.DataFactory.blankNode() : rdfn3.DataFactory.namedNode(graph_names[i]);
                            for (const q of graphs[i]) {
                                retval.add(rdfn3.DataFactory.quad(q.subject,q.predicate,q.object,graphID));
                            }
                        }
                        return retval;
                    }
                })();
                rdfn3.write_quads(proof, output);
            }
        }
    }
})()
