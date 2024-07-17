// test refreshing tokens

import * as dotenv from 'dotenv';
dotenv.config({ path: 'tests/.env' }); // Adjust the path as necessary
import assert from 'assert';
import Fastify, { FastifyInstance, LightMyRequestResponse } from 'fastify';
import jws from 'jws'
import { LoginSyncParams } from '@hellocoop/fastify';
import jwkToPem, { JWK } from 'jwk-to-pem'
import { webcrypto, createHash, randomUUID } from 'crypto';
const { subtle } = webcrypto;

import { api, loginSync } from '../src/api';
import {
    API_ROOT,
    TOKEN_ENDPOINT,
    INTROSPECTION_ENDPOINT,
    ACCESS_LIFETIME,
    REFRESH_LIFETIME,
} from '../src/constants'

import { TEST_USER } from './user';

const USE_DPOP: boolean = !!process.env.OAUTH_DPOP

const SDK_CLIENT_ID = 'sdk-1.0.0'

const extractable = true
const keyUsages: KeyUsage[] = ['sign','verify']

const algorithmRS256 = { // https://developer.mozilla.org/en-US/docs/Web/API/RsaHashedKeyGenParams
    name:           'RSASSA-PKCS1-v1_5',
    modulusLength:  2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash:           'SHA-256'
}

let privateKeyPem: string
let publicKeyJWK: JWK
let publicKeyThumbprint: string

const generateThumbprint = function(jwk: JWK) {
    const ordered = JSON.stringify(jwk, Object.keys(jwk).sort());
    const hash = createHash('sha256').update(ordered).digest('base64url');
    return hash;
}

const generateKeys = async function() {
    try { // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey
        const cryptoKeyPair = await subtle.generateKey(algorithmRS256,extractable,keyUsages)
        const privateKeyJWK = await subtle.exportKey('jwk',cryptoKeyPair.privateKey) as JWK
        privateKeyPem = jwkToPem(privateKeyJWK, { private: true })
        publicKeyJWK = await subtle.exportKey('jwk',cryptoKeyPair.publicKey) as JWK
        publicKeyThumbprint = generateThumbprint(publicKeyJWK)
    } catch(e) {
        console.error(e)
        return e
    }
}

const makeDPoP = function (): string {
    const dpop: string = jws.sign({
        header: {
            alg: 'RS256',
            typ: 'dpop+jwt',
            jwk: publicKeyJWK
        },
        payload: {
            htm: 'POST',
            htu: `http://localhost:3000${TOKEN_ENDPOINT}`,
            jti: randomUUID(),
            iat: Math.floor(Date.now() / 1000),
        },
        privateKey: privateKeyPem
    })
    return dpop
}


describe('Refresh Token', () => {
    let app: FastifyInstance
    let response: LightMyRequestResponse
    let nonce: string
    let refresh_token: string
    let access_token: string
    let jwks_uri: string
    let issuerPublicKeyPem: string
    let kid: string

    before(async () => {
        await generateKeys()
        app = Fastify();
        api(app);
        response = await app.inject({
            method: 'POST',
            url: TOKEN_ENDPOINT,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
              },
            payload: `grant_type=cookie_token&client_id=${SDK_CLIENT_ID}`  
        });
    });

    it('should return issuer', async () => {
        const response = await app.inject({
            method: 'GET',
            url: '/.well-known/oauth-authorization-server'
        });
    
        assert.strictEqual(response.statusCode, 200, 'Status code is not 200');
        const json = response.json();
        assert(json, 'Response is not JSON');
        assert.strictEqual(json.issuer, 'http://localhost:3000', 'Issuer does not match');
        jwks_uri = json.jwks_uri;
        assert(jwks_uri, 'jwks_uri does not exist');
    });

    it('should return jwks', async () => {
        const response = await app.inject({
            method: 'GET',
            url: jwks_uri
        });
    
        assert.strictEqual(response.statusCode, 200, 'Status code is not 200');
        const json = response.json();
        assert(json, 'Response is not JSON');

        const { keys } = json;
        assert(keys, 'Keys do not exist');
        assert(keys.length > 0, 'Keys are empty');
        const key = keys[0];
        assert(key, 'Key does not exist');
        assert.strictEqual(key.kty, 'RSA', 'Key kty is not RSA');
        assert(key.kid, 'Key kid does not exist');
        kid = key.kid;
        issuerPublicKeyPem = jwkToPem(key);
        assert(issuerPublicKeyPem, 'issuerPublicKeyPem does not exist');
        assert(issuerPublicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----'), 'issuerPublicKeyPem is not a public key');
    });
    
    it('should return nonce', async () => {    
        assert.strictEqual(response.statusCode, 200, 'Status code is not 200');
        const json = response.json();
        const loggedIn = json.loggedIn;
        assert(loggedIn === false, 'User is logged in')
        nonce = json.nonce;
        assert(nonce, 'Nonce does not exist');
    })

    it ('should accept a login trigger', async () => {
        const user: Record<string, any> = TEST_USER;
        user.nonce = nonce;
        const response = await loginSync({payload: user} as unknown as LoginSyncParams);
        assert.strictEqual(Object.keys(response).length, 0, 'Response is not an empty object');
    })

    it ('should return an access_token and refresh_token', async () => {
        const headers: Record<string, any> = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        if (USE_DPOP) {
            const DPoP = await makeDPoP()
            headers['DPoP'] = DPoP
        }
        const response = await app.inject({
            method: 'POST',
            url: TOKEN_ENDPOINT,
            headers,
            payload: `grant_type=authorization_code&client_id=${SDK_CLIENT_ID}&code=${nonce}`  
        });
        assert.strictEqual(response.statusCode, 200, 'Status code is not 200');
        const json = response.json();
        assert(json, 'Response is not JSON');
        ({ access_token, refresh_token } = json)
        assert(access_token, 'access_token does not exist');
        assert(refresh_token, 'refresh_token does not exist');
        assert.strictEqual(json.expires_in, ACCESS_LIFETIME, `expires_in is not ${ACCESS_LIFETIME}`);
        if (USE_DPOP) {
            assert.strictEqual(json.token_type, 'DPoP', 'token_type is not DPoP');
        } else {
            assert.strictEqual(json.token_type, 'Bearer', 'token_type is not Bearer');
        }
        const { header: accessHeader, payload: accessPayload } = jws.decode(access_token, { json: true });
        assert(accessHeader, 'access_token cookie value is not a valid JWT');
        assert.strictEqual(accessHeader.alg, 'RS256', 'access_token alg is not RS256');
        assert.strictEqual(accessHeader.typ, 'at+jwt', 'access_token typ is not at+jwt');
        assert.strictEqual(accessHeader.kid, kid, 'access_token kid is not the same as the jwks kid')
        if (USE_DPOP) {
            assert(accessPayload?.cnf?.jkt, 'access_token cnf.jkt does not exist');
            assert.strictEqual(accessPayload?.cnf?.jkt, publicKeyThumbprint, 'access_token cnf.jkt is not the same as our thumbprint');
        }
        const accessValid = jws.verify(access_token, 'RS256', issuerPublicKeyPem);
        assert(accessValid, 'access_token is not valid');
        assert.strictEqual(accessPayload.iss, "http://localhost:3000", 'access_token iss is not http://localhost:3000');
        assert.strictEqual(accessPayload.client_id, SDK_CLIENT_ID, `access_token aud is not ${SDK_CLIENT_ID}`);
        assert.strictEqual(accessPayload.exp - accessPayload.iat, ACCESS_LIFETIME, `access_token exp - iat is not ${ACCESS_LIFETIME}`);
        assert.strictEqual(accessPayload.token_type, 'access_token', 'access_token token_type is not access_token');
        const { header: refreshHeader, payload: refreshPayload } = jws.decode(refresh_token, { json: true });
        assert(refreshHeader, 'refresh_token cookie value is not a valid JWT');
        assert.strictEqual(refreshHeader.alg, 'RS256', 'refresh_token alg is not RS256');
        assert.strictEqual(refreshHeader.kid, kid, 'refresh_token kid is not the same as the jwks kid');
        if (USE_DPOP) {
            assert(refreshPayload?.cnf?.jkt, 'refresh_token cnf.jkt does not exist');
            assert.strictEqual(refreshPayload?.cnf?.jkt, publicKeyThumbprint, 'refresh_token cnf.jkt is not the same as our thumbprint');
        }
        const refreshValid = jws.verify(refresh_token, 'RS256', issuerPublicKeyPem);
        assert(refreshValid, 'refresh_token cookie is not valid');
        assert.strictEqual(refreshPayload.iss, "http://localhost:3000", 'refresh_token iss is not http://localhost:3000');
        assert.strictEqual(refreshPayload.client_id, SDK_CLIENT_ID, `refresh_token aud is not ${SDK_CLIENT_ID}`);
        assert.strictEqual(refreshPayload.exp - refreshPayload.iat, REFRESH_LIFETIME, `refresh_token exp - iat is not ${REFRESH_LIFETIME}`);
        assert.strictEqual(refreshPayload.token_type, 'refresh_token', 'refresh_token token_type is not refresh_token');
    })

    it ('should accept a refresh token and return new access_token and refresh_token', async () => {
        const headers: Record<string, any> = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        if (USE_DPOP) {
            const DPoP = await makeDPoP()
            headers['DPoP'] = DPoP
        }
        const response = await app.inject({
            method: 'POST',
            url: TOKEN_ENDPOINT,
            headers,
            payload: `grant_type=refresh_token&client_id=${SDK_CLIENT_ID}&refresh_token=${refresh_token}`  
        });
        assert.strictEqual(response.statusCode, 200, 'Status code is not 200');
        const json = response.json();
        const { access_token: newAccessToken, refresh_token: newRefreshToken } = json
        assert(newAccessToken, 'access_token does not exist');
        assert(newRefreshToken, 'refresh_token does not exist');
        assert.strictEqual(json.expires_in, ACCESS_LIFETIME, `expires_in is not ${ACCESS_LIFETIME}`);
        const { header: accessHeader, payload: accessPayload } = jws.decode(newAccessToken, { json: true });
        assert(accessHeader, 'access_token cookie value is not a valid JWT');
        assert.strictEqual(accessHeader.alg, 'RS256', 'access_token alg is not RS256');
        assert.strictEqual(accessHeader.typ, 'at+jwt', 'access_token typ is not at+jwt');
        assert.strictEqual(accessHeader.kid, kid, 'access_token kid is not the same as the jwks kid')
        if (USE_DPOP) {
            assert(accessPayload?.cnf?.jkt, 'access_token cnf.jkt does not exist');
            assert.strictEqual(accessPayload?.cnf?.jkt, publicKeyThumbprint, 'access_token cnf.jkt is not the same as our thumbprint');
        }        
        const accessValid = jws.verify(newAccessToken, 'RS256', issuerPublicKeyPem);
        assert(accessValid, 'access_token is not valid');
        assert.strictEqual(accessPayload.iss, "http://localhost:3000", 'access_token iss is not http://localhost:3000');
        assert.strictEqual(accessPayload.client_id, SDK_CLIENT_ID, `access_token aud is not ${SDK_CLIENT_ID}`);
        assert.strictEqual(accessPayload.exp - accessPayload.iat, ACCESS_LIFETIME, `access_token exp - iat is not ${ACCESS_LIFETIME}`);
        assert.strictEqual(accessPayload.token_type, 'access_token', 'access_token token_type is not access_token');
        const { header: refreshHeader, payload: refreshPayload } = jws.decode(newRefreshToken, { json: true });
        assert(refreshHeader, 'refresh_token cookie value is not a valid JWT');
        assert.strictEqual(refreshHeader.alg, 'RS256', 'refresh_token alg is not RS256');
        assert.strictEqual(refreshHeader.kid, kid, 'refresh_token kid is not the same as the jwks kid');
        if (USE_DPOP) {
            assert(refreshPayload?.cnf?.jkt, 'refresh_token cnf.jkt does not exist');
            assert.strictEqual(refreshPayload?.cnf?.jkt, publicKeyThumbprint, 'refresh_token cnf.jkt is not the same as our thumbprint');
        }        
        const refreshValid = jws.verify(newRefreshToken, 'RS256', issuerPublicKeyPem);
        assert(refreshValid, 'refresh_token cookie is not valid');
        assert.strictEqual(refreshPayload.iss, "http://localhost:3000", 'refresh_token iss is not http://localhost:3000');
        assert.strictEqual(refreshPayload.client_id, SDK_CLIENT_ID, `refresh_token aud is not ${SDK_CLIENT_ID}`);
        assert.strictEqual(refreshPayload.exp - refreshPayload.iat, REFRESH_LIFETIME, `refresh_token exp - iat is not ${REFRESH_LIFETIME}`);
        assert.strictEqual(refreshPayload.token_type, 'refresh_token', 'refresh_token token_type is not refresh_token');

        assert.notStrictEqual(newAccessToken, access_token, 'access_token value has not changed');
        assert.notStrictEqual(newRefreshToken, refresh_token, 'refresh_token value has not changed');
    })

    it ('should introspect the access token', async () => {
        const headers: Record<string, any> = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        const response = await app.inject({
            method: 'POST',
            url: INTROSPECTION_ENDPOINT,
            headers,
            payload: `token=${access_token}`  
        });
        assert.strictEqual(response.statusCode, 200, 'Status code is not 200');
        const json = response.json();
        assert(json, 'Response is not JSON');
        assert.strictEqual(json.active, true, 'Token is not active');
        assert.strictEqual(json.client_id, SDK_CLIENT_ID, `client_id is not ${SDK_CLIENT_ID}`);
        assert.strictEqual(json.iss, "http://localhost:3000", 'iss is not http://localhost:3000');
        assert.strictEqual(json.token_type, 'access_token', 'token_type is not access_token');
        assert.strictEqual(json.sub, TEST_USER.sub, `sub is not ${TEST_USER.sub}`);
        if (USE_DPOP) {
            assert.strictEqual(json?.cnf?.jkt, publicKeyThumbprint, 'cnf.jkt is not the same as our thumbprint');
        }
    })

})
