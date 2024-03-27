// test the cookie_token flow

import * as dotenv from 'dotenv';
dotenv.config({ path: 'tests/.env' }); // Adjust the path as necessary
import assert from 'assert';
import Fastify, { FastifyInstance, LightMyRequestResponse } from 'fastify';
import jws from 'jws'
import { LoginSyncParams } from '@hellocoop/fastify';
import { api, loginSync } from '../src/api';
import {
    API_ROOT,
    TOKEN_ENDPOINT,
    ACCESS_LIFETIME,
    STATE_LIFETIME,
    REFRESH_LIFETIME,
} from '../src/constants'

import { PUBLIC_KEY } from '../src/jwks';

import { TEST_USER } from './user';

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
    let session_token: string
    let refresh_token: string
    let access_token: string

    before(async () => {
        app = Fastify();
        api(app);
        response = await app.inject({
            method: 'POST',
            url: TOKEN_ENDPOINT,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'x-test': 'test1',
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
        const sessionCookie = cookies['session_token'];
        assert(sessionCookie.httpOnly, 'session_token cookie is not httpOnly');
        assert(sessionCookie.sameSite, 'session_token cookie does not have sameSite');
        assert.strictEqual(sessionCookie.sameSite, 'Strict', 'session_token cookie sameSite is not Strict');
        assert(sessionCookie.maxAge, 'session_token cookie does not have maxAge');
        assert.strictEqual(sessionCookie.maxAge, STATE_LIFETIME, `session_token cookie maxAge is not ${STATE_LIFETIME}`);
        assert.strictEqual(sessionCookie.path, TOKEN_ENDPOINT, `session_token cookie path is ${TOKEN_ENDPOINT}`);
        session_token = sessionCookie.value;
        assert(session_token, 'session_token cookie value does not exist');
        const { header, payload } = jws.decode(session_token, { json: true });
        assert(header, 'session_token cookie value is not a valid JWT');
        assert.strictEqual(header.alg, 'RS256', 'session_token alg is not RS256');
        const valid = jws.verify(sessionCookie.value, 'RS256', PUBLIC_KEY);
        assert(valid, 'session_token cookie is not valid');

        assert.strictEqual(payload.iss, "http://localhost:3000", 'session_token iss is not http://localhost:3000');
        assert.strictEqual(payload.client_id, WEBVIEW_CLIENT_ID, `session_token aud is not ${WEBVIEW_CLIENT_ID}`);
        assert.strictEqual(payload.nonce, nonce, 'session_token nonce does not match returned nonce');
        assert.strictEqual(payload.exp - payload.iat, STATE_LIFETIME, `session_token exp - iat is not ${STATE_LIFETIME}`);
        assert.strictEqual(payload.token_type, 'session_token', 'session_token token_type is not session_token');
    })


    it ('should accept a login trigger', async () => {
        const user: Record<string, any> = TEST_USER;
        user.nonce = nonce;
        const response = await loginSync({payload: user} as unknown as LoginSyncParams);
        assert.strictEqual(Object.keys(response).length, 0, 'Response is not an empty object');
    })

    it ('should now have a logged in user and cookie tokens', async () => {
        const response = await app.inject({
            method: 'POST',
            url: TOKEN_ENDPOINT,
            headers: {
                'x-test': 'test3',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': `session_token=${session_token}`,
              },
            payload: `grant_type=cookie_token&client_id=${WEBVIEW_CLIENT_ID}`  
        });
        assert.strictEqual(response.statusCode, 200, 'Status code is not 200');
        const json = response.json();
        const loggedIn = json.loggedIn;
        assert(loggedIn === true, 'User is not logged in');
        const cookies = getCookies(response as unknown as { cookies: Cookie[] })
        assert(cookies['access_token'], 'access_token cookie does not exist');
        assert(cookies['refresh_token'], 'refresh_token cookie does not exist');
        const accessCookie = cookies['access_token'];
        const refreshCookie = cookies['refresh_token'];
        assert(accessCookie.httpOnly, 'access_token cookie is not httpOnly');
        assert(accessCookie.sameSite, 'access_token cookie does not have sameSite');
        assert.strictEqual(accessCookie.sameSite, 'Strict', 'access_token cookie sameSite is not Strict');
        assert(accessCookie.maxAge, 'access_token cookie does not have maxAge');
        assert.strictEqual(accessCookie.maxAge, ACCESS_LIFETIME, `access_token cookie maxAge is not ${ACCESS_LIFETIME}`);
        assert.strictEqual(accessCookie.path, API_ROOT, `access_token cookie path is not ${API_ROOT}`);
        assert(refreshCookie.httpOnly, 'refresh_token cookie is not httpOnly');
        assert(refreshCookie.sameSite, 'refresh_token cookie does not have sameSite');
        assert.strictEqual(refreshCookie.sameSite, 'Strict', 'refresh_token cookie sameSite is not Strict');
        assert(refreshCookie.maxAge, 'refresh_token cookie does not have maxAge');
        assert.strictEqual(refreshCookie.maxAge, REFRESH_LIFETIME, `refresh_token cookie maxAge is not ${REFRESH_LIFETIME}`);
        assert.strictEqual(refreshCookie.path, TOKEN_ENDPOINT, `refresh_token cookie path is not ${TOKEN_ENDPOINT}`);
        const { header: accessHeader, payload: accessPayload } = jws.decode(accessCookie.value, { json: true });
        assert(accessHeader, 'access_token cookie value is not a valid JWT');
        assert.strictEqual(accessHeader.alg, 'RS256', 'access_token alg is not RS256');
        assert.strictEqual(accessHeader.typ, 'at+jwt', 'access_token typ is not at+jwt');
        const accessValid = jws.verify(accessCookie.value, 'RS256', PUBLIC_KEY);
        assert(accessValid, 'access_token cookie is not valid');
        assert.strictEqual(accessPayload.iss, "http://localhost:3000", 'access_token iss is not http://localhost:3000');
        assert.strictEqual(accessPayload.client_id, WEBVIEW_CLIENT_ID, `access_token aud is not ${WEBVIEW_CLIENT_ID}`);
        assert.strictEqual(accessPayload.exp - accessPayload.iat, ACCESS_LIFETIME, `access_token exp - iat is not ${ACCESS_LIFETIME}`);
        assert.strictEqual(accessPayload.token_type, 'access_token', 'access_token token_type is not access_token');
        const { header: refreshHeader, payload: refreshPayload } = jws.decode(refreshCookie.value, { json: true });
        assert(refreshHeader, 'refresh_token cookie value is not a valid JWT');
        assert.strictEqual(refreshHeader.alg, 'RS256', 'refresh_token alg is not RS256');
        const refreshValid = jws.verify(refreshCookie.value, 'RS256', PUBLIC_KEY);
        assert(refreshValid, 'refresh_token cookie is not valid');
        assert.strictEqual(refreshPayload.iss, "http://localhost:3000", 'refresh_token iss is not http://localhost:3000');
        assert.strictEqual(refreshPayload.client_id, WEBVIEW_CLIENT_ID, `refresh_token aud is not ${WEBVIEW_CLIENT_ID}`);
        assert.strictEqual(refreshPayload.exp - refreshPayload.iat, REFRESH_LIFETIME, `refresh_token exp - iat is not ${REFRESH_LIFETIME}`);
        assert.strictEqual(refreshPayload.token_type, 'refresh_token', 'refresh_token token_type is not refresh_token');
        refresh_token = refreshCookie.value;
        access_token = accessCookie.value;
    })

    it ('should accept a refresh token', async () => {
        const response = await app.inject({
            method: 'POST',
            url: TOKEN_ENDPOINT,
            headers: {
                'x-test': 'test4',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': `refresh_token=${refresh_token}; access_token=${access_token}`,
              },
            payload: `grant_type=cookie_token&client_id=${WEBVIEW_CLIENT_ID}`  
        });
        assert.strictEqual(response.statusCode, 200, 'Status code is not 200');
        const json = response.json();
        const loggedIn = json.loggedIn;
        assert(loggedIn === true, 'User is not logged in');
        const cookies = getCookies(response as unknown as { cookies: Cookie[] })

        assert(cookies['session_token'], 'session_token cookie does not exist');
        const sessionCookie = cookies['session_token'];
        assert.strictEqual(sessionCookie.maxAge, 0, 'session_token cookie maxAge is not zero');
        assert.strictEqual(sessionCookie.value, '', 'session_token cookie value is not empty');

        assert(cookies['access_token'], 'access_token cookie does not exist');
        const accessCookie = cookies['access_token'];
        assert(accessCookie.httpOnly, 'access_token cookie is not httpOnly');
        assert(accessCookie.sameSite, 'access_token cookie does not have sameSite');
        assert.strictEqual(accessCookie.sameSite, 'Strict', 'access_token cookie sameSite is not Strict');
        assert(accessCookie.maxAge, 'access_token cookie does not have maxAge');
        assert.strictEqual(accessCookie.maxAge, ACCESS_LIFETIME, `access_token cookie maxAge is not ${ACCESS_LIFETIME}`);
        assert.strictEqual(accessCookie.path, API_ROOT, `access_token cookie path is not ${API_ROOT}`);

        assert(cookies['refresh_token'], 'refresh_token cookie does not exist');
        const refreshCookie = cookies['refresh_token'];
        assert(refreshCookie.httpOnly, 'refresh_token cookie is not httpOnly');
        assert(refreshCookie.sameSite, 'refresh_token cookie does not have sameSite');
        assert.strictEqual(refreshCookie.sameSite, 'Strict', 'refresh_token cookie sameSite is not Strict');
        assert(refreshCookie.maxAge, 'refresh_token cookie does not have maxAge');
        assert.strictEqual(refreshCookie.maxAge, REFRESH_LIFETIME, `refresh_token cookie maxAge is not ${REFRESH_LIFETIME}`);
        assert.strictEqual(refreshCookie.path, TOKEN_ENDPOINT, `refresh_token cookie path is not ${TOKEN_ENDPOINT}`);

        const { header: accessHeader, payload: accessPayload } = jws.decode(accessCookie.value, { json: true });
        assert(accessHeader, 'access_token cookie value is not a valid JWT');
        assert.strictEqual(accessHeader.alg, 'RS256', 'access_token alg is not RS256');
        assert.strictEqual(accessHeader.typ, 'at+jwt', 'access_token typ is not at+jwt');
        const accessValid = jws.verify(accessCookie.value, 'RS256', PUBLIC_KEY);
        assert(accessValid, 'access_token cookie is not valid');
        assert.strictEqual(accessPayload.iss, "http://localhost:3000", 'access_token iss is not http://localhost:3000');
        assert.strictEqual(accessPayload.client_id, WEBVIEW_CLIENT_ID, `access_token aud is not ${WEBVIEW_CLIENT_ID}`);
        assert.strictEqual(accessPayload.exp - accessPayload.iat, ACCESS_LIFETIME, `access_token exp - iat is not ${ACCESS_LIFETIME}`);
        assert.strictEqual(accessPayload.token_type, 'access_token', 'access_token token_type is not access_token');

        const { header: refreshHeader, payload: refreshPayload } = jws.decode(refreshCookie.value, { json: true });
        assert(refreshHeader, 'refresh_token cookie value is not a valid JWT');
        assert.strictEqual(refreshHeader.alg, 'RS256', 'refresh_token alg is not RS256');
        const refreshValid = jws.verify(refreshCookie.value, 'RS256', PUBLIC_KEY);
        assert(refreshValid, 'refresh_token cookie is not valid');
        assert.strictEqual(refreshPayload.iss, "http://localhost:3000", 'refresh_token iss is not http://localhost:3000');
        assert.strictEqual(refreshPayload.client_id, WEBVIEW_CLIENT_ID, `refresh_token aud is not ${WEBVIEW_CLIENT_ID}`);
        assert.strictEqual(refreshPayload.exp - refreshPayload.iat, REFRESH_LIFETIME, `refresh_token exp - iat is not ${REFRESH_LIFETIME}`);
        assert.strictEqual(refreshPayload.token_type, 'refresh_token', 'refresh_token token_type is not refresh_token');

        assert.notStrictEqual(accessCookie.value, access_token, 'access_token value has not changed');
        assert.notStrictEqual(refreshCookie.value, refresh_token, 'refresh_token value has not changed');
    })

})
