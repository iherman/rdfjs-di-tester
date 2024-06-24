import { Command }  from 'commander';
import * as di      from 'rdfjs-di';
import * as process from 'node:process';


async function generateKey(suite: di.Cryptosuites, keyData?: di.KeyDetails): Promise<di.KeyData> {
    const suiteToAPI = (): RsaHashedKeyGenParams | EcKeyGenParams => {
        switch (suite) {
            case di.Cryptosuites.ecdsa: return {
                name: "ECDSA",
                namedCurve: keyData?.namedCurve || "P-256",
            } as EcKeyGenParams;
            case di.Cryptosuites.eddsa: return {
                name: "Ed25519"
            } as EcKeyGenParams;
            case di.Cryptosuites.rsa_pss: return {
                name: "RSA-PSS",
                modulusLength: keyData?.modulusLength || 2048,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: keyData?.hash || "SHA-256",
            } as RsaHashedKeyGenParams;
            case di.Cryptosuites.rsa_ssa: return {
                name: 'RSASSA-PKCS1-v1_5',
                modulusLength: keyData?.modulusLength || 2048,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: keyData?.hash || "SHA-256",
            } as RsaHashedKeyGenParams;
        }
    };

    const keys: CryptoKeyPair = await crypto.subtle.generateKey(suiteToAPI(), true, ["sign", "verify"]);

    return {
        public      : await crypto.subtle.exportKey('jwk', keys.publicKey),
        private     : await crypto.subtle.exportKey('jwk', keys.privateKey),
        controller  : "https://www.ivan-herman.name/foaf#me",
        expires     : "2055-02-24T00:00",
        cryptosuite : suite 
    }
}


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
    const keys = await generateKey(suite);
    console.log(JSON.stringify(keys,null,4));
})();

