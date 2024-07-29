import fs from 'fs';
import path from 'path';
import jwkToPem, { JWK } from 'jwk-to-pem';
import { promisify } from 'util';
import * as logger from './logger';

const readFile = promisify(fs.readFile);

interface RSA_JWK {
    kty: string;
    n: string;
    e: string;
    alg: string;
    kid: string;
    use?: string;
    key_ops?: string[];
}

interface JWKS {
    keys: RSA_JWK[];
}

const isValidJWKS = (jwks: JWKS): boolean => {
    return Array.isArray(jwks.keys) && jwks.keys.every((key) => key.kty && key.e && key.n);
}

let PRIVATE_KEY: string;
let PUBLIC_KEY: string;
let PUBLIC_JWKS: JWKS;

const loadKeys = (): void => {

    const filePath = path.join(__dirname, '..', 'keys', 'privateJWKS.json');

    if (!fs.existsSync(filePath)) {
        throw new Error(`"${filePath}" does not exist`);
    }

    let jwks: JWKS;
    try {
        const fileContent = fs.readFileSync(filePath, 'utf-8');
        jwks = JSON.parse(fileContent);
    } catch (error) {
        throw new Error('Invalid JSON');
    }

    if (!isValidJWKS(jwks)) {
        throw new Error('Invalid JWKS');
    }

    PRIVATE_KEY = jwkToPem(jwks.keys[0] as JWK, { private: true });

    // Extract the public JWKs from the private JWKs
    PUBLIC_JWKS = {
        keys: jwks.keys.map((key) => ({
            kty: key.kty,
            n: key.n,
            e: key.e,
            alg: key.alg,
            kid: key.kid,
            use: 'sig',
            key_ops: ['verify']
        }))
    };

    PUBLIC_KEY = jwkToPem(PUBLIC_JWKS.keys[0] as JWK);
}

try {
    loadKeys();
} catch (error) {
    logger.error("failed to load JWKS keys", logger.formatError(error));
}

export { PRIVATE_KEY, PUBLIC_KEY, PUBLIC_JWKS };
