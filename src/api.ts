// server

import fastify from 'fastify';
import jws from 'jws'
import jwkToPem from 'jwk-to-pem'
import { jwkThumbprintByEncoding } from 'jwk-thumbprint';
import { randomUUID } from 'crypto';

import { JWKS, PRIVATE_KEY, PUBLIC_KEY } from './jwks'
import * as state from './state'

const BASE_URL = 'http://localhost:3000'
const TOKEN_ENDPOINT = '/token'
const REVOCATION_ENDPOINT = '/revoke'
const JWKS_ENDPOINT = '/jwks'
const LOGIN_ENDPOINT = '/login'

const HTU = BASE_URL + TOKEN_ENDPOINT

const PORT = 8080

const ACCESS_LIFETIME = 5 * 60              // 5 minutes
const STATE_LIFETIME = 5 * 60               // 5 minutes
const REFRESH_LIFETIME = 30 * 24 * 60 * 60  // 30 days
const DPOP_LIFETIME = 60                    // 1 minute for clock skew

const JWT_HEADER = {
    alg: JWKS.keys[0].alg,
    typ: 'JWT',
    kid: JWKS.keys[0].kid
}

class TokenError extends Error {
    statusCode: number; 
  
    constructor(statusCode: number, message: string) {
      super(message);
      this.statusCode = statusCode || 500
      Object.setPrototypeOf(this, TokenError.prototype); // Fix prototype chain
      Error.captureStackTrace(this, this.constructor);
    }
}

const validateDPoP = (req): string => {
    const dpop = req.headers['DPoP']
    if (!dpop) {
        throw new TokenError(400, 'DPoP header is required')
    }
    const { header, payload } = jws.decode(dpop)
    if (!header || !payload) {
        throw new TokenError(400, 'DPoP header is invalid')
    }
    const { typ, alg, jwk } = header
    if (typ !== 'dpop+jwt') {
        throw new TokenError(400, 'DPoP typ is invalid')
    }
    if (META_DATA.dpop_signing_alg_values_supported.indexOf(alg) === -1){
        throw new TokenError(400, 'DPoP alg is invalid')
    }
    if (!jwk) {
        throw new TokenError(400, 'DPoP header is invalid')
    }
    const { jti, htm, htu, iat } = payload
    if (!jti || !htm || !htu || !iat) {
        throw new TokenError(400, 'DPoP payload is invalid')
    }
    const now = Math.floor(Date.now() / 1000)
    if (iat + DPOP_LIFETIME < now) {
        throw new TokenError(400, 'DPoP is expired')
    }
    if (htm !== 'POST') {
        throw new TokenError(400, 'DPoP method is invalid')
    }
    if (htu !== HTU) {
        throw new TokenError(400, 'DPoP path is invalid')
    }
    const pem = jwkToPem(jwk)
    try {
        const decoded = jws.verify(dpop, alg, pem)
    } catch (e) {
        throw new TokenError(400, 'DPoP signature is invalid')
    }
    const jkt = jwkThumbprintByEncoding(jwk, 'SHA-256', 'base64url')
    return jkt
}   

const refreshFromCode = (code: string, jwt?: string): string => {
    // lookup code and get payload 

    const payload = {
    } as any

    if (jwt) {
        payload.cnf = {
            jkt: jwt
        }
    }
    payload.token_type = 'refresh_token'
    const now = Math.floor(Date.now() / 1000)
    payload.iat = now
    payload.exp = now + REFRESH_LIFETIME
    const refresh_token = jws.sign({
        header: JWT_HEADER,
        payload,
        privateKey: PRIVATE_KEY
    })
    return refresh_token
}

const refreshFromRefresh = (refresh_token: string, jwt?: string): string => {
    const { header, payload } = jws.decode(refresh_token)
    if (!header || !payload) {
        throw new TokenError(400, 'refresh_token is invalid')
    }
    try {
        const decoded = jws.verify(refresh_token, header.alg, PUBLIC_KEY)
    } catch (e) {
        throw new 
        TokenError(400, 'refresh_token is invalid')
    }
    const now = Math.floor(Date.now() / 1000)
    if (payload.exp < now) {
        throw new TokenError(400, 'refresh_token is expired')
    }

// FUTURE -- check if user has been logged out since refresh_token was issued

    payload.iat = now
    payload.exp = now + ACCESS_LIFETIME
    const newRefreshToken = jws.sign({
        header: JWT_HEADER,
        payload,
        privateKey: PRIVATE_KEY
    })
    return newRefreshToken}

const refreshFromSession = async (session_token: string) => {
    // lookup session_token and get payload 
    const { header, payload } = jws.decode(session_token)
    // TODO -- verify session_token
    if (!header || !payload) {
        throw new TokenError(400, 'session_token is invalid')
    }
    if (payload.token_type !== 'session_token') {
        throw new TokenError(400, 'session_token is invalid')
    }
    const now = Math.floor(Date.now() / 1000)
    // check if expired
    if (payload.exp < now) {
        throw new TokenError(400, 'session_token is expired')
    }
    const currentState = await state.read(payload.nonce)
    if (!currentState) {
        throw new TokenError(400, 'session state has expired')
    }
    if (!currentState.loggedIn) {
        throw new TokenError(400, 'session state is not logged in')
    }
    if (currentState.iss !== BASE_URL) {
        throw new TokenError(400, 'session_token invalid issuer')
    }
    const refreshPayload = {
        iss: BASE_URL,
        sub: currentState.sub,
        client_id: payload.client_id,
        token_type: 'refresh_token',
        iat: now,
        exp: now + REFRESH_LIFETIME
    }
    const newRefreshToken = jws.sign({
        header: JWT_HEADER,
        payload: refreshPayload,
        privateKey: PRIVATE_KEY
    })
    return newRefreshToken
}

const accessFromRefresh = (refresh_token: string): string => {
    const { header, payload } = jws.decode(refresh_token)
    if (!header || !payload) {
        throw new TokenError(400, 'refresh_token is invalid')
    }
    try {
        const decoded = jws.verify(refresh_token, header.alg, PUBLIC_KEY)
    } catch (e) {
        throw new 
        TokenError(400, 'refresh_token is invalid')
    }
    const now = Math.floor(Date.now() / 1000)
    // check if expired 
    if (payload.exp < now) {
        throw new TokenError(400, 'refresh_token is expired')
    }
    delete payload.token_type
    payload.iat = now
    payload.exp = now + ACCESS_LIFETIME
    const newAccessToken = jws.sign({
        header: JWT_HEADER,
        payload,
        privateKey: PRIVATE_KEY
    })
    return newAccessToken
}

const makeSessionToken = async (client_id): Promise<{session_token: string, nonce: string}> => {
    const nonce = randomUUID()
    const now = Math.floor(Date.now() / 1000)
    const currentState: state.State = {
        iss: BASE_URL,
        loggedIn: false,
        exp: now + STATE_LIFETIME,
        nonce
    }
    await state.create(nonce, currentState)
    const session_token = jws.sign({
        header: JWT_HEADER,
        payload: {
            token_type: 'session_token',
            iss: BASE_URL,
            iat: now,
            exp: now + STATE_LIFETIME,
            client_id,
            nonce
        },
        privateKey: PRIVATE_KEY
    })
    return { session_token, nonce }
}

const tokenEndpoint = async (req, res) => {
    const { grant_type, client_id, refresh_token, code } = req.body

    try {
        if (grant_type === 'authorization_code') {
            if (!client_id) {
                return res.code(400).send({error:'invalid_request', error_description:'client_id is required'})
            }
            if (!code) {
                return res.code(400).send({error:'invalid_request', error_description:'code is required'})
            }
            const jwt = validateDPoP(req)
            const newRefreshToken = refreshFromCode(code, jwt)
            const newAccessToken = accessFromRefresh(newRefreshToken)
            return res.send({
                access_token: newAccessToken,
                token_type: 'DPoP',
                expires_in: ACCESS_LIFETIME,
                refresh_token: newRefreshToken
            })
        }

        if (grant_type === 'refresh_token') {
            if (!refresh_token){ 
                return res.code(400).send({error:'invalid_request', error_description:'refresh_token is required'})
            }
            const jwt = validateDPoP(req)
            const newRefreshToken = refreshFromRefresh(refresh_token, jwt)
            const newAccessToken = accessFromRefresh(newRefreshToken)
            return res.send({
                access_token: newAccessToken,
                token_type: 'DPoP',
                expires_in: ACCESS_LIFETIME,
                refresh_token: newRefreshToken
            })
        }

        if (grant_type === 'cookie_token') { // non-standard
            if (!client_id) {
                return res.code(400).send({error:'invalid_request', error_description:'client_id is required'})
            }
            const { session_token, refresh_token } = req.cookies
            if (!session_token && !refresh_token) {
                // no existing session
                const { session_token, nonce } = await makeSessionToken(client_id)
                res.setCookie('session_token', session_token, { path: TOKEN_ENDPOINT })
                return res.send({
                    loggedIn: false,
                    nonce
                })
            }

            // we have an existing session
            const newRefreshToken = (session_token)
                ? await refreshFromSession(session_token)
                : refreshFromRefresh(refresh_token)
            const newAccessToken = accessFromRefresh(newRefreshToken)
            res.setCookie('access_token', newAccessToken, { path: '/' })
            res.setCookie('refresh_token', newRefreshToken, { path: TOKEN_ENDPOINT })
            return res.send({
                loggedIn: true
            })
        }

        if (grant_type === 'client_credentials') {
            return res.code(501).send('Not Implemented')
        }
        res.code(400).send({error:'unsupported_grant_type'})
    } catch (e) {
        const error = e as TokenError
        console.error(error)
        res.code(error.statusCode).send({error: error.message})
    }
}

const loginEndpoint = async (req, res) => {
    const id_token = req.body.id_token
    if (!id_token) {
        return res.code(400).send({error:'invalid_request', error_description:'id_token is required'})
    }
    const { header, payload } = jws.decode(id_token)
    if (!header || !payload) {
        return res.code(400).send({error:'invalid_request', error_description:'id_token is invalid'})
    }
    // TODO verify id_token
    // TODO create or update user

    const { sub, nonce } = payload
    const currentState = await state.read(nonce)
    if (!currentState) {
        return res.code(400).send({error:'invalid_request', error_description:'nonce is invalid'})
    }
    if (currentState.loggedIn) {
        return res.code(400).send({error:'invalid_request', error_description:'nonce is already logged in'})
    }
    const now = Math.floor(Date.now() / 1000)
    if (currentState.exp < now) {
        return res.code(400).send({error:'invalid_request', error_description:'state has expired'})
    }

    await state.update(nonce, { 
        iss: BASE_URL,
        exp: now + STATE_LIFETIME,
        nonce,
        loggedIn: true, 
        sub 
    })
    res.code(202)
}

const app = fastify({
    // TBD
});

app.post(LOGIN_ENDPOINT, loginEndpoint)

app.post(TOKEN_ENDPOINT, tokenEndpoint)

app.post(REVOCATION_ENDPOINT, (req, res) => {
    res.code(501).send('Not Implemented')
})

app.get(JWKS_ENDPOINT, (req, res) => {
    res.send(JWKS)
})

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
        'RS256','ES256'
    ],    
}
app.get('/.well-known/oauth-authorization-server', (req, res) => {
    res.send(META_DATA)
})

console.log('/.well-known/oauth-authorization-server', JSON.stringify(META_DATA, null, 2))

app.listen({ port: PORT }, function (err, address) {
    if (err) {
      console.error(err);
      process.exit(1);
    }
    console.log(`server listening on ${address}`);
})