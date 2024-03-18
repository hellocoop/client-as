import assert from 'assert';
import Fastify, { FastifyInstance, LightMyRequestResponse } from 'fastify';
import jws from 'jws'

import { api } from '../src/api';
import {
    TOKEN_ENDPOINT,
    REVOCATION_ENDPOINT,
    JWKS_ENDPOINT,
    LOGIN_ENDPOINT,
    ACCESS_LIFETIME,
    STATE_LIFETIME,
    REFRESH_LIFETIME,
    DPOP_LIFETIME
} from '../src/constants'

import { PUBLIC_KEY } from '../src/jwks';

const WEBVIEW_CLIENT_ID = 'webview-1.0.0'

interface Cookie {
    name: string;
    value: string;
    [key: string]: string | boolean;
}
  
const getCookies = (response: { cookies: Cookie[] }): { [key: string]: Cookie } => {
    const cookieList = response.cookies;
    const cookies: { [key: string]: Cookie } = {};

    cookieList.forEach((cookie) => {
        cookies[cookie.name] = cookie;
    });
    return cookies; 
};

describe('Cookie Token', () => {
    let app: FastifyInstance
    let response: LightMyRequestResponse
    let nonce: string

    before(async () => {
        app = Fastify();
        api(app);
        response = await app.inject({
            method: 'POST',
            url: '/token',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
              },
            payload: `grant_type=cookie_token&client_id=${WEBVIEW_CLIENT_ID}`  
        });
    });
    
    it('should return nonce', async () => {    
        assert.strictEqual(response.statusCode, 200, 'Status code is not 200');
        const json = response.json();
        const loggedIn = json.loggedIn;
        assert(loggedIn === false, 'User is logged in')
        nonce = json.nonce;
        assert(nonce, 'Nonce does not exist');
    })

    it ('should return a session_token cookie', async () => {
        const cookies = getCookies(response as unknown as { cookies: Cookie[] })
        assert(cookies['session_token'], 'session_token cookie does not exist');
        const sessionToken = cookies['session_token'];
        assert(sessionToken.httpOnly, 'session_token cookie is not httpOnly');
        assert(sessionToken.sameSite, 'session_token cookie does not have sameSite');
        assert.strictEqual(sessionToken.sameSite, 'Strict', 'session_token cookie sameSite is not Strict');
        assert(sessionToken.maxAge, 'session_token cookie does not have maxAge');
        assert.strictEqual(sessionToken.maxAge, STATE_LIFETIME, `session_token cookie maxAge is not ${STATE_LIFETIME}`);
        assert.strictEqual(sessionToken.path, TOKEN_ENDPOINT, `session_token cookie path is not ${TOKEN_ENDPOINT}`);

        const { header, payload } = jws.decode(sessionToken.value, { json: true });
        assert(header, 'session_token cookie value is not a valid JWT');
        assert.strictEqual(header.alg, 'RS256', 'session_token alg is not RS256');
        const valid = jws.verify(sessionToken.value, 'RS256', PUBLIC_KEY);
        assert(valid, 'session_token cookie is not valid');

        assert.strictEqual(payload.iss, "http://localhost:3000", 'session_token iss is not http://localhost:3000');
        assert.strictEqual(payload.client_id, WEBVIEW_CLIENT_ID, `session_token aud is not ${WEBVIEW_CLIENT_ID}`);
        assert.strictEqual(payload.nonce, nonce, 'session_token nonce does not match returned nonce');
        assert.strictEqual(payload.exp - payload.iat, STATE_LIFETIME, `session_token exp - iat is not ${STATE_LIFETIME}`);
        assert.strictEqual(payload.token_type, 'session_token', 'session_token token_type is not session_token');
    })
})
