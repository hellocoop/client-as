import { webcrypto } from 'crypto'
const { subtle } = webcrypto;
import { nanoid } from 'nanoid'

const extractable = true
const keyUsages = ['sign','verify']
const algorithmRS256 = { 
    name:           'RSASSA-PKCS1-v1_5',
    modulusLength:  2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash:           'SHA-256'
}

const generateKeys = async function() {
    try { 
        const cryptoKeyPair = await subtle.generateKey(algorithmRS256,extractable,keyUsages)
        const privateKeyJWK = await subtle.exportKey('jwk',cryptoKeyPair.privateKey)
        privateKeyJWK.kid = nanoid()
        return { keys: [privateKeyJWK] }
    } catch(e) {
        console.error(e)
        return e
    }
}

const isValidJWKS = (jwks) => {
    return Array.isArray(jwks.keys) && jwks.keys.every(key => key.kty && key.e && key.n);
}

; (async () => {
    try {
        const keys = await generateKeys();

        let jwksData = '';
        process.stdin.on('data', (chunk) => {
            jwksData += chunk;
        });

        process.stdin.on('end', () => {
            let jwks = { keys: [] };
            try {
                if (jwksData !== '') {
                    jwks = JSON.parse(jwksData);
                    if (!isValidJWKS(jwks)) {
                        throw new Error('Invalid JWKS');
                    }
                }
                jwks.keys.unshift(keys.keys[0]);
                while (jwks.keys.length > 3) {
                    jwks.keys.pop();
                }
                process.stdout.write(JSON.stringify(jwks, null, 2));
            } catch (error) {
                console.error('Invalid JSON or JWKS format');
                process.exit(1);
            }
        });
    } catch (error) {
        console.error(error);
    }
})();