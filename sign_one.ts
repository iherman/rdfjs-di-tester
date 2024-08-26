// deno-lint-ignore-file require-await verbatim-module-syntax
import * as rdf     from '@rdfjs/types';
import { Command }  from 'commander';
import * as di      from 'rdfjs-di';
import * as process from 'node:process';
import * as path    from 'node:path';
import * as fs      from 'node:fs/promises';
import * as rdfn3   from './lib/rdfn3';

interface JWKKeyPair {
    publicKey: JsonWebKey,
    privateKey: JsonWebKey,
    controller?: string,
    expires?: string;
}

async function get_key(keyref: string): Promise<di.KeyData> {
    // combine the HOME with the key directory and the keyref to get
    const key_file: string = path.join(process.env.KEY_ENV ?? "", keyref) + '.json';
    const raw_keys: string = await fs.readFile(key_file, 'utf-8');
    const jwkKeyPair: JWKKeyPair = JSON.parse(raw_keys) as JWKKeyPair;
    return {
        publicKey: await di.jwkToCrypto(jwkKeyPair.publicKey, false),
        privateKey: await di.jwkToCrypto(jwkKeyPair.privateKey, true),
        controller: jwkKeyPair?.controller,
        expires: jwkKeyPair?.expires
    };
}

(async (): Promise<void> => {
    const program = new Command();
    program
        .name('sign [options] file')
        .description('Signing an RDF dataset or graph')
        .usage('[options] [file name]')
        .option('-a, --anchor <anchor>', 'Anchor the proof graph to the file name (if applicable)')
        .option('-e, --embed', 'Create an embedded proof')
        .option('-k, --key <keyref>', 'Key reference')
        .option('-o, --output <output>', 'Output file')
        .parse(process.argv);

    const options = program.opts();

    const embed = options.embed ? true : false;
    const anchor: string | undefined = options.anchor;
    const output: string | undefined = options.output;
    const key_reference: string = options.key ?? "eddsa";

    if (program.args.length === 0) {
        console.log('No dataset reference')
    } else {
        const file_name = program.args[0];
        // Get the key
        const key_pair = await get_key(key_reference);

        // Get the graph
        const dataset: rdf.DatasetCore = await rdfn3.get_quads(file_name);

        const proof: rdf.DatasetCore = await (async (): Promise<rdf.DatasetCore> => {
            if (embed) {
                return di.embedProofGraph(dataset, key_pair, anchor ? rdfn3.DataFactory.namedNode(anchor) : undefined);
            } else {
                return di.generateProofGraph(dataset, key_pair)
            }
        })();
        rdfn3.write_quads(proof, output);
    }
})()
