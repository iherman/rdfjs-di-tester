import { Command }  from 'commander';
import * as di      from 'rdfjs-di';
import * as process from 'node:process';


(async () : Promise<void> => {
    const program = new Command();
    program 
        .name("di_createKey")
        .description("Create new keypair. Crypto name must be one of 'ecdsa', 'eddsa', 'rsa_pss', or 'rsa_ssa'.")
        .usage('cryptoname')
        .parse(process.argv);

    const _options = program.opts();
    const input = (program.args.length === 0) ? "eddsa" : program.args[0];

    const suite = ((crypto: string): di.Cryptosuites => {
        switch (crypto) {
            case "ecdsa": return di.Cryptosuites.ecdsa;
            case "eddsa": return di.Cryptosuites.eddsa;
            case "rsa_pss": return di.Cryptosuites.rsa_pss;
            case "rsa_ssa": return di.Cryptosuites.rsa_ssa;
        }
        throw new Error("Unknown crypto name. Should be one of 'ecdsa', 'eddsa', 'rsa_pss', or 'rsa_ssa'.");
    })(input);

    const cryptoKeys: di.KeyData = await di.generateKey(suite);
    const toStore = {
        publicKey  : await crypto.subtle.exportKey("jwk", cryptoKeys.publicKey),
        privateKey : await crypto.subtle.exportKey("jwk", cryptoKeys.privateKey),
        controller : "https://www.ivan-herman.name/foaf#me",
        expires    : "2055-02-24T00:00"
    }
    console.log(JSON.stringify(toStore,null,4));
})();

