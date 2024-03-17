"use strict";
// server
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.PORT = exports.api = void 0;
const formbody_1 = __importDefault(require("@fastify/formbody"));
const jws_1 = __importDefault(require("jws"));
const jwk_to_pem_1 = __importDefault(require("jwk-to-pem"));
const jwk_thumbprint_1 = require("jwk-thumbprint");
const crypto_1 = require("crypto");
const cookie_1 = require("cookie");
const jwks_1 = require("./jwks");
const state = __importStar(require("./state"));
const HOST = process.env.HOST;
const PORT = Number(process.env.PORT) || 3000;
exports.PORT = PORT;
const BASE_URL = (HOST)
    ? `https://${HOST}`
    : `http://localhost:${PORT}`;
const TOKEN_ENDPOINT = '/token';
const REVOCATION_ENDPOINT = '/revoke';
const JWKS_ENDPOINT = '/jwks';
const LOGIN_ENDPOINT = '/login';
const HTU = BASE_URL + TOKEN_ENDPOINT;
const ACCESS_LIFETIME = 5 * 60; // 5 minutes
const STATE_LIFETIME = 5 * 60; // 5 minutes
const REFRESH_LIFETIME = 30 * 24 * 60 * 60; // 30 days
const DPOP_LIFETIME = 60; // 1 minute for clock skew
const PRODUCTION = (process.env.NODE_ENV === 'production');
const JWT_HEADER = {
    alg: 'RS256',
    typ: 'jwt',
    kid: jwks_1.JWKS.keys[0].kid
};
const AT_HEADER = {
    alg: 'RS256',
    typ: 'at+jwt',
    kid: jwks_1.JWKS.keys[0].kid
};
// OAuth 2.0 Authorization Server Metadata
const META_DATA = {
    issuer: BASE_URL,
    token_endpoint: `${BASE_URL}${TOKEN_ENDPOINT}`,
    jwks_uri: `${BASE_URL}${JWKS_ENDPOINT}`,
    grant_types_supported: [
        'authorization_code',
        'client_credentials',
        'refresh_token',
        'cookie_token', // non-standard
    ],
    revocation_endpoint: `${BASE_URL}${REVOCATION_ENDPOINT}`,
    dpop_signing_alg_values_supported: [
        'RS256', 'ES256'
    ],
};
// console.log('/.well-known/oauth-authorization-server', JSON.stringify(META_DATA, null, 2))
class TokenError extends Error {
    statusCode;
    constructor(statusCode, message) {
        super(message);
        this.statusCode = statusCode || 500;
        Object.setPrototypeOf(this, TokenError.prototype); // Fix prototype chain
        Error.captureStackTrace(this, this.constructor);
    }
}
const setTokenCookies = (reply, access_token, refresh_token) => {
    const accessTokenCookie = (0, cookie_1.serialize)('access_token', access_token || '', {
        maxAge: access_token ? ACCESS_LIFETIME : 0,
        httpOnly: true,
        path: '/',
        secure: PRODUCTION,
        sameSite: 'strict',
    });
    const refreshTokenCookie = (0, cookie_1.serialize)('refresh_token', refresh_token || '', {
        maxAge: refresh_token ? REFRESH_LIFETIME : 0,
        httpOnly: true,
        path: TOKEN_ENDPOINT,
        secure: PRODUCTION,
        sameSite: 'strict',
    });
    reply.header('Set-Cookie', [accessTokenCookie, refreshTokenCookie]);
};
const setSessionCookie = (reply, session_token) => {
    const sessionTokenCookie = (0, cookie_1.serialize)('session_token', session_token || '', {
        maxAge: session_token ? STATE_LIFETIME : 0,
        httpOnly: true,
        path: TOKEN_ENDPOINT,
        secure: PRODUCTION,
        sameSite: 'strict',
    });
    reply.header('Set-Cookie', sessionTokenCookie);
};
const getCookies = (req) => {
    const cookies = req.headers['cookie'];
    if (!cookies) {
        return {};
    }
    return (0, cookie_1.parse)(cookies);
};
const validateDPoP = (req) => {
    const dpop = req.headers['DPoP'];
    if (!dpop) {
        throw new TokenError(400, 'DPoP header is required');
    }
    if (Array.isArray(dpop)) {
        throw new TokenError(400, 'Only one DPoP header is allowed');
    }
    const { header, payload } = jws_1.default.decode(dpop);
    if (!header || !payload) {
        throw new TokenError(400, 'DPoP header is invalid');
    }
    const { typ, alg, jwk } = header;
    if (typ !== 'dpop+jwt') {
        throw new TokenError(400, 'DPoP typ is invalid');
    }
    if (META_DATA.dpop_signing_alg_values_supported.indexOf(alg) === -1) {
        throw new TokenError(400, 'DPoP alg is invalid');
    }
    if (!jwk) {
        throw new TokenError(400, 'DPoP header is invalid');
    }
    const { jti, htm, htu, iat } = payload;
    if (!jti || !htm || !htu || !iat) {
        throw new TokenError(400, 'DPoP payload is invalid');
    }
    const now = Math.floor(Date.now() / 1000);
    if (iat + DPOP_LIFETIME < now) {
        throw new TokenError(400, 'DPoP is expired');
    }
    if (htm !== 'POST') {
        throw new TokenError(400, 'DPoP method is invalid');
    }
    if (htu !== HTU) {
        throw new TokenError(400, 'DPoP path is invalid');
    }
    const pem = (0, jwk_to_pem_1.default)(jwk);
    try {
        const decoded = jws_1.default.verify(dpop, alg, pem);
    }
    catch (e) {
        throw new TokenError(400, 'DPoP signature is invalid');
    }
    const jkt = (0, jwk_thumbprint_1.jwkThumbprintByEncoding)(jwk, 'SHA-256', 'base64url');
    return jkt;
};
const refreshFromCode = async (code, client_id, jkt) => {
    const currentState = await state.read(code);
    if (!currentState) {
        throw new TokenError(400, 'code is invalid');
    }
    if (!currentState.loggedIn) {
        throw new TokenError(400, 'code is not logged in');
    }
    if (currentState.iss !== BASE_URL) {
        throw new TokenError(400, 'code invalid issuer');
    }
    const now = Math.floor(Date.now() / 1000);
    if (currentState.exp < now) {
        throw new TokenError(400, 'code is expired');
    }
    // check one time use of code
    if (currentState.code_used) {
        // future - logout user to revoke issued refresh_token
        throw new TokenError(400, 'code has already been used');
    }
    currentState.code_used = now;
    await state.update(code, currentState);
    const payload = {
        iss: BASE_URL,
        sub: currentState.sub,
        aud: currentState.aud,
        client_id,
        token_type: 'refresh_token',
        iat: now,
        exp: now + REFRESH_LIFETIME,
        jti: (0, crypto_1.randomUUID)(),
        cnf: {
            jkt: jkt
        }
    };
    payload.token_type = 'refresh_token';
    payload.iat = now;
    payload.exp = now + REFRESH_LIFETIME;
    const refresh_token = jws_1.default.sign({
        header: JWT_HEADER,
        payload,
        privateKey: jwks_1.PRIVATE_KEY
    });
    return refresh_token;
};
const refreshFromRefresh = (refresh_token) => {
    const { header, payload } = jws_1.default.decode(refresh_token);
    if (!header || !payload) {
        throw new TokenError(400, 'refresh_token is invalid');
    }
    try {
        const decoded = jws_1.default.verify(refresh_token, header.alg, jwks_1.PUBLIC_KEY);
    }
    catch (e) {
        throw new TokenError(400, 'refresh_token is invalid');
    }
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) {
        throw new TokenError(400, 'refresh_token is expired');
    }
    // FUTURE -- check if user has been logged out since refresh_token was issued
    payload.iat = now;
    payload.exp = now + ACCESS_LIFETIME;
    const newRefreshToken = jws_1.default.sign({
        header: JWT_HEADER,
        payload,
        privateKey: jwks_1.PRIVATE_KEY
    });
    return newRefreshToken;
};
const refreshFromSession = async (session_token) => {
    // lookup session_token and get payload 
    const { header, payload } = jws_1.default.decode(session_token);
    // TODO -- verify session_token
    if (!header || !payload) {
        throw new TokenError(400, 'session_token is invalid');
    }
    if (payload.token_type !== 'session_token') {
        throw new TokenError(400, 'session_token is invalid');
    }
    const now = Math.floor(Date.now() / 1000);
    // check if expired
    if (payload.exp < now) {
        throw new TokenError(400, 'session_token is expired');
    }
    const currentState = await state.read(payload.nonce);
    if (!currentState) {
        throw new TokenError(400, 'session state has expired');
    }
    if (!currentState.loggedIn) {
        throw new TokenError(400, 'session state is not logged in');
    }
    if (currentState.iss !== BASE_URL) {
        throw new TokenError(400, 'session_token invalid issuer');
    }
    const refreshPayload = {
        iss: BASE_URL,
        sub: currentState.sub,
        aud: currentState.aud,
        client_id: payload.client_id,
        token_type: 'refresh_token',
        iat: now,
        exp: now + REFRESH_LIFETIME,
        jti: (0, crypto_1.randomUUID)()
    };
    const newRefreshToken = jws_1.default.sign({
        header: JWT_HEADER,
        payload: refreshPayload,
        privateKey: jwks_1.PRIVATE_KEY
    });
    return newRefreshToken;
};
const accessFromRefresh = (refresh_token) => {
    const { header, payload } = jws_1.default.decode(refresh_token);
    if (!header || !payload) {
        throw new TokenError(400, 'refresh_token is invalid');
    }
    if (payload.token_type !== 'refresh_token') {
        throw new TokenError(400, 'refresh_token is invalid');
    }
    const now = Math.floor(Date.now() / 1000);
    // check if expired 
    if (payload.exp < now) {
        throw new TokenError(400, 'refresh_token is expired');
    }
    try {
        const decoded = jws_1.default.verify(refresh_token, header.alg, jwks_1.PUBLIC_KEY);
    }
    catch (e) {
        throw new TokenError(400, 'refresh_token is invalid');
    }
    payload.token_type = 'access_token';
    payload.iat = now;
    payload.exp = now + ACCESS_LIFETIME;
    payload.jwi = (0, crypto_1.randomUUID)();
    const newAccessToken = jws_1.default.sign({
        header: AT_HEADER,
        payload,
        privateKey: jwks_1.PRIVATE_KEY
    });
    return newAccessToken;
};
const makeSessionToken = async (client_id) => {
    const nonce = (0, crypto_1.randomUUID)();
    const now = Math.floor(Date.now() / 1000);
    const currentState = {
        iss: BASE_URL,
        loggedIn: false,
        exp: now + STATE_LIFETIME,
        nonce
    };
    await state.create(nonce, currentState);
    const session_token = jws_1.default.sign({
        header: JWT_HEADER,
        payload: {
            token_type: 'session_token',
            iss: BASE_URL,
            iat: now,
            exp: now + STATE_LIFETIME,
            client_id,
            nonce
        },
        privateKey: jwks_1.PRIVATE_KEY
    });
    return { session_token, nonce };
};
const tokenEndpoint = async (req, reply) => {
    const { grant_type, client_id, refresh_token, code } = req.body;
    try {
        if (grant_type === 'authorization_code') {
            if (!client_id) {
                return reply.code(400).send({ error: 'invalid_request', error_description: 'client_id is required' });
            }
            if (!code) {
                return reply.code(400).send({ error: 'invalid_request', error_description: 'code is required' });
            }
            const jkt = validateDPoP(req);
            const newRefreshToken = await refreshFromCode(code, client_id, jkt);
            const newAccessToken = accessFromRefresh(newRefreshToken);
            return reply.send({
                access_token: newAccessToken,
                token_type: 'DPoP',
                expires_in: ACCESS_LIFETIME,
                refresh_token: newRefreshToken
            });
        }
        if (grant_type === 'refresh_token') {
            if (!refresh_token) {
                return reply.code(400).send({ error: 'invalid_request', error_description: 'refresh_token is required' });
            }
            const jwk = validateDPoP(req);
            const { payload } = jws_1.default.decode(refresh_token);
            if (!payload?.cnf?.jkt) {
                throw new TokenError(400, 'refresh_token is invalid');
            }
            if (payload.cnt.jkt !== jwk) {
                throw new TokenError(400, 'DPoP jkt does not match refresh_token jkt');
            }
            const newRefreshToken = refreshFromRefresh(refresh_token);
            const newAccessToken = accessFromRefresh(newRefreshToken);
            return reply.send({
                access_token: newAccessToken,
                token_type: 'DPoP',
                expires_in: ACCESS_LIFETIME,
                refresh_token: newRefreshToken
            });
        }
        if (grant_type === 'cookie_token') { // non-standard
            if (!client_id) {
                return reply.code(400).send({ error: 'invalid_request', error_description: 'client_id is required' });
            }
            const { session_token, refresh_token } = getCookies(req);
            if (!session_token && !refresh_token) {
                // no existing session
                const { session_token, nonce } = await makeSessionToken(client_id);
                setSessionCookie(reply, session_token);
                return reply.send({
                    loggedIn: false,
                    nonce
                });
            }
            // we have an existing session
            const newRefreshToken = (session_token)
                ? await refreshFromSession(session_token)
                : refreshFromRefresh(refresh_token);
            const newAccessToken = accessFromRefresh(newRefreshToken);
            setTokenCookies(reply, newAccessToken, newRefreshToken);
            return reply.send({
                loggedIn: true
            });
        }
        if (grant_type === 'client_credentials') {
            return reply.code(501).send('Not Implemented');
        }
        reply.code(400).send({ error: 'unsupported_grant_type' });
    }
    catch (e) {
        const error = e;
        console.error(error);
        reply.code(error.statusCode).send({ error: error.message });
    }
};
const loginEndpoint = async (req, reply) => {
    const { sub, nonce } = req.body;
    if (!sub) {
        return reply.code(400).send({ error: 'invalid_request', error_description: 'sub is required' });
    }
    if (!nonce) {
        return reply.code(400).send({ error: 'invalid_request', error_description: 'nonce is required' });
    }
    const currentState = await state.read(nonce);
    if (!currentState) {
        return reply.code(400).send({ error: 'invalid_request', error_description: 'nonce is invalid' });
    }
    if (currentState.loggedIn) {
        return reply.code(400).send({ error: 'invalid_request', error_description: 'nonce is already logged in' });
    }
    const now = Math.floor(Date.now() / 1000);
    if (currentState.exp < now) {
        return reply.code(400).send({ error: 'invalid_request', error_description: 'state has expired' });
    }
    await state.update(nonce, {
        iss: BASE_URL,
        exp: now + STATE_LIFETIME,
        nonce,
        loggedIn: true,
        sub
    });
    reply.code(202);
};
const api = (app) => {
    app.register(formbody_1.default);
    app.post(LOGIN_ENDPOINT, loginEndpoint);
    app.post(TOKEN_ENDPOINT, tokenEndpoint);
    app.post(REVOCATION_ENDPOINT, (req, reply) => {
        reply.code(501).send('Not Implemented');
    });
    app.get(JWKS_ENDPOINT, (req, reply) => {
        reply.send(jwks_1.JWKS);
    });
    app.get('/.well-known/oauth-authorization-server', (req, reply) => {
        reply.send(META_DATA);
    });
};
exports.api = api;
