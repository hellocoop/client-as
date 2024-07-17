// server

import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import formbody from '@fastify/formbody';
import jws, { Algorithm, Header } from 'jws'
import jwkToPem, { JWK } from 'jwk-to-pem'
import { randomUUID, createHash } from 'crypto';
import { serialize as serializeCookie, parse as parseCookies } from 'cookie'
import { helloAuth, HelloConfig, LoginSyncParams, LoginSyncResponse, LogoutSyncParams, LogoutSyncResponse } from '@hellocoop/fastify'

import { PUBLIC_JWKS, PRIVATE_KEY, PUBLIC_KEY } from './jwks'
import * as state from './state'

import {
    API_ROOT,
    AUTH_ROUTE,
    TOKEN_ENDPOINT,
    REVOCATION_ENDPOINT,
    JWKS_ENDPOINT,
    INTROSPECTION_ENDPOINT,
    ACCESS_LIFETIME,
    STATE_LIFETIME,
    REFRESH_LIFETIME,
    DPOP_LIFETIME,
    LOGOUT_ENDPOINT
} from './constants'
import { log } from 'console';
import { create } from 'domain';
import { stat } from 'fs';

interface Payload {
    iss: string
    sub: string
    aud: string
    token_type: string
    iat: number
    exp: number
    jti: string
    cnf?: {
        jkt: string
    },
    client_id?: string
    hello_sub?: string
    scope?: string
}

const HOST = process.env.HOST
const PORT: number = Number(process.env.PORT) || 3000
const USE_DPOP: boolean = !!process.env.OAUTH_DPOP

const ISSUER = (HOST)
? `https://${HOST}`
: `http://localhost:${PORT}`
const HTU = ISSUER + TOKEN_ENDPOINT

const PRODUCTION = (process.env.NODE_ENV === 'production')
const ENABLE_3P_COOKIES = (process.env.ENABLE_3P_COOKIES === 'true')
const SAME_SITE = (ENABLE_3P_COOKIES) ? 'none' : 'strict'
const SECURE = PRODUCTION || ENABLE_3P_COOKIES

const { version } = require('../package.json')

const clientId = process.env.CLIENT_ID || process.env.HELLO_CLIENT_ID
const cookieSecret = process.env.COOKIE_SECRET || process.env.HELLO_COOKIE_SECRET

if (!clientId) {
    throw new Error('CLIENT_ID or HELLO_CLIENT_ID is required')
}
if (!cookieSecret) {
    throw new Error('COOKIE_SECRET or HELLO_COOKIE_SECRET is required')
}



const JWT_HEADER: Header = {
    alg: 'RS256',
    typ: 'jwt',
    kid: PUBLIC_JWKS.keys[0].kid
}
const AT_HEADER: Header = {
    alg: 'RS256',
    typ: 'at+jwt',
    kid: PUBLIC_JWKS.keys[0].kid
}

// OAuth 2.0 Authorization Server Metadata
interface MetaData {
    issuer: string;
    token_endpoint: string;
    jwks_uri: string;
    grant_types_supported: string[];
    revocation_endpoint: string;
    dpop_signing_alg_values_supported?: string[];
}
const META_DATA: MetaData = {
    issuer: ISSUER,
    token_endpoint: TOKEN_ENDPOINT,
    jwks_uri: JWKS_ENDPOINT,
    grant_types_supported: [
        'authorization_code',
        'client_credentials',
        'refresh_token',
        'cookie_token', // non-standard
    ],
    revocation_endpoint: REVOCATION_ENDPOINT,
}
if (USE_DPOP) {
    META_DATA.dpop_signing_alg_values_supported = ['RS256']
}


console.log('/.well-known/oauth-authorization-server', JSON.stringify(META_DATA, null, 2))

class TokenError extends Error {
    statusCode: number;

    constructor(statusCode: number, message: string) {
      super(message);
      this.statusCode = statusCode || 500
      Object.setPrototypeOf(this, TokenError.prototype); // Fix prototype chain
      Error.captureStackTrace(this, this.constructor);
    }
}

const generateThumbprint = function(jwk: JWK) {
    const ordered = JSON.stringify(jwk, Object.keys(jwk).sort());
    const hash = createHash('sha256').update(ordered).digest('base64url');
    return hash;
}

const createTokenCookies = ( access_token: string, refresh_token: string) => {

    const accessTokenCookie = serializeCookie('access_token', access_token || '', {
        maxAge: access_token ? ACCESS_LIFETIME : 0,
        httpOnly: true,
        path: API_ROOT,
        secure: SECURE,
        sameSite: SAME_SITE,
    })

    const refreshTokenCookie = serializeCookie('refresh_token', refresh_token || '', {
        maxAge: refresh_token ? REFRESH_LIFETIME : 0,
        httpOnly: true,
        path: TOKEN_ENDPOINT,
        secure: SECURE,
        sameSite: SAME_SITE,
    })

    // always clear session_token
    const sessionTokenCookie = serializeCookie('session_token', '', {
        maxAge: 0,
        httpOnly: true,
        path: TOKEN_ENDPOINT,
        secure: SECURE,
        sameSite: SAME_SITE,
    })

    return [accessTokenCookie, refreshTokenCookie, sessionTokenCookie]
}

const setSessionCookie = (reply: FastifyReply, session_token: string) => {

    const sessionTokenCookie = serializeCookie('session_token', session_token || '', {
        maxAge: session_token ? STATE_LIFETIME : 0,
        httpOnly: true,
        path: TOKEN_ENDPOINT,
        secure: SECURE,
        sameSite: SAME_SITE,
    })
    reply.header('Set-Cookie', sessionTokenCookie);
}

const getCookies = (req: FastifyRequest): Record<string, string> => {
    const cookies = req.headers['cookie']
    if (!cookies) {
        return {}
    }
    return parseCookies(cookies)
}

const validateDPoP = (req: FastifyRequest): string => {
    if (!USE_DPOP)
        return ''
    const dpop = req.headers['dpop']
    if (!dpop) {
        throw new TokenError(400, 'DPoP header is required')
    }
    if (Array.isArray(dpop)) {
        throw new TokenError(400, 'Only one DPoP header is allowed')
    }
    const { header, payload } = jws.decode(dpop as string, { json: true }) || {} as jws.Signature
    if (!header || !payload) {
        throw new TokenError(400, 'DPoP header is invalid')
    }
    const { typ, alg, jwk } = header as { typ: string, alg: Algorithm, jwk: JWK}
    if (typ !== 'dpop+jwt') {
        throw new TokenError(400, 'DPoP typ is invalid')
    }
    if (META_DATA?.dpop_signing_alg_values_supported?.indexOf(alg) === -1){
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

    if (!jws.verify(dpop, alg, pem))
        throw new TokenError(400, 'DPoP signature is invalid')
    const jkt = generateThumbprint(jwk)
    return jkt
}

const refreshFromCode = async (code: string, client_id: string, jkt: string): Promise<string> => {
    const currentState = await state.read(code)
    if (!currentState) {
        throw new TokenError(400, 'code is invalid')
    }
    if (!currentState.loggedIn) {
        throw new TokenError(400, 'code is not logged in')
    }
    if (currentState.iss !== ISSUER) {
        throw new TokenError(400, 'code invalid issuer')
    }
    const now = Math.floor(Date.now() / 1000)
    if (currentState.exp !== undefined && currentState.exp < now) {
        throw new TokenError(400, 'code is expired')
    }
    // check one time use of code
    if (currentState.code_used) {
        // future - logout user to revoke issued refresh_token
        throw new TokenError(400, 'code has already been used')
    }
    if (currentState.client_id &&  currentState.client_id !== client_id) {
        throw new TokenError(400, 'code client_id does not match')
    }
    currentState.code_used = now
    await state.update(code, currentState)

    const payload: Payload = {
        iss: ISSUER,
        sub: currentState.sub,
        aud: currentState.aud,
        hello_sub: currentState.hello_sub,
        scope: currentState.scope,
        client_id,
        token_type: 'refresh_token',
        iat: now,
        exp: now + REFRESH_LIFETIME,
        jti: randomUUID(),
    }
    if (USE_DPOP) {
        payload.cnf = {
            jkt: jkt
        }
    }

    payload.token_type = 'refresh_token'
    payload.iat = now
    payload.exp = now + REFRESH_LIFETIME
    const refresh_token = jws.sign({
        header: JWT_HEADER,
        payload,
        privateKey: PRIVATE_KEY
    })
    return refresh_token
}

const refreshFromRefresh = (refresh_token: string): string => {
    const { header, payload } = jws.decode(refresh_token, { json: true }) || {} as jws.Signature
    if (!header || !payload) {
        throw new TokenError(400, 'refresh_token is invalid')
    }
    if (!jws.verify(refresh_token, header.alg, PUBLIC_KEY))
        throw new TokenError(400, 'refresh_token is invalid')
    const now = Math.floor(Date.now() / 1000)
    if (payload.exp < now) {
        throw new TokenError(400, 'refresh_token is expired')
    }

// FUTURE -- check if user has been logged out since refresh_token was issued

    payload.iat = now
    payload.exp = now + REFRESH_LIFETIME
    payload.jti = randomUUID()
    const newRefreshToken = jws.sign({
        header: JWT_HEADER,
        payload,
        privateKey: PRIVATE_KEY
    })
    return newRefreshToken
}

const refreshFromSession = async (session_token: string) => {
    // lookup session_token and get payload
    const { header, payload } = jws.decode(session_token, { json: true }) || {} as jws.Signature
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
    if (currentState.iss !== ISSUER) {
        throw new TokenError(400, 'session_token invalid issuer')
    }
    const refreshPayload: Payload = {
        iss: ISSUER,
        sub: currentState.sub as string,
        aud: currentState.aud as string,
        hello_sub: currentState.hello_sub,
        scope: currentState.scope,
        client_id: currentState.client_id,
        token_type: 'refresh_token',
        iat: now,
        exp: now + REFRESH_LIFETIME,
        jti: randomUUID()
    }
    const newRefreshToken = jws.sign({
        header: JWT_HEADER,
        payload: refreshPayload,
        privateKey: PRIVATE_KEY
    })
    return newRefreshToken
}

const accessFromRefresh = (refresh_token: string): string => {
    const { header, payload } = jws.decode(refresh_token, { json: true }) || {} as jws.Signature
    if (!header || !payload) {
        throw new TokenError(400, 'refresh_token is invalid')
    }
    if (payload.token_type !== 'refresh_token') {
        throw new TokenError(400, 'refresh_token is invalid')
    }
    const now = Math.floor(Date.now() / 1000)
    // check if expired
    if (payload.exp < now) {
        throw new TokenError(400, 'refresh_token is expired')
    }
    if (!jws.verify(refresh_token, header.alg, PUBLIC_KEY))
        throw new TokenError(400, 'refresh_token is invalid')
    payload.token_type = 'access_token'
    payload.iat = now
    payload.exp = now + ACCESS_LIFETIME
    payload.jwi = randomUUID()
    const newAccessToken = jws.sign({
        header: AT_HEADER,
        payload,
        privateKey: PRIVATE_KEY
    })
    return newAccessToken
}

const makeSessionToken = async (origin: state.Origin): Promise<{session_token: string, nonce: string}> => {
    const nonce = randomUUID()
    const now = Math.floor(Date.now() / 1000)
    const currentState: state.State = {
        loggedIn: false,
        iss: ISSUER,
        exp: now + STATE_LIFETIME,
        nonce,
        origin,
    }
    await state.create(nonce, currentState)
    const params = {
        header: JWT_HEADER,
        payload: {
            token_type: 'session_token',
            iss: ISSUER,
            iat: now,
            exp: now + STATE_LIFETIME,
            nonce,
        },
        privateKey: PRIVATE_KEY
    }

    const session_token = jws.sign(params)
    return { session_token, nonce }
}

const tokenEndpoint = async (req: FastifyRequest, reply: FastifyReply) => {
    const { grant_type, client_id, refresh_token, code } = req.body as
        { grant_type: string, client_id: string, refresh_token: string, code: string}

    // console.log({grant_type, headers: req.headers, cookies: req.headers['cookie']})


    try {
        if (grant_type === 'authorization_code') {
            if (!client_id) {
                return reply.code(400).send({error:'invalid_request', error_description:'client_id is required'})
            }
            if (!code) {
                return reply.code(400).send({error:'invalid_request', error_description:'code is required'})
            }
            const jkt = validateDPoP(req)
            const newRefreshToken = await refreshFromCode(code, client_id, jkt)
            const newAccessToken = accessFromRefresh(newRefreshToken)
            return reply.send({
                access_token: newAccessToken,
                token_type: USE_DPOP ? 'DPoP' : 'Bearer',
                expires_in: ACCESS_LIFETIME,
                refresh_token: newRefreshToken
            })
        }

        if (grant_type === 'refresh_token') {
            if (!refresh_token){
                return reply.code(400).send({error:'invalid_request', error_description:'refresh_token is required'})
            }
            const jwt = validateDPoP(req)

            const { payload } = jws.decode(refresh_token, { json: true }) || {} as jws.Signature
            if (USE_DPOP) {
                if (!payload?.cnf?.jkt) {
                    throw new TokenError(400, 'refresh_token is invalid')
                }
                if (payload.cnf.jkt !== jwt) {
                    throw new TokenError(400, 'DPoP jkt does not match refresh_token jkt')
                }
            }
            if (!jws.verify(refresh_token, 'RS256', PUBLIC_KEY))
                throw new TokenError(400, 'refresh_token is invalid')
            const newRefreshToken = refreshFromRefresh(refresh_token)
            const newAccessToken = accessFromRefresh(newRefreshToken)
            return reply.send({
                access_token: newAccessToken,
                token_type: USE_DPOP ? 'DPoP' : 'Bearer',
                expires_in: ACCESS_LIFETIME,
                refresh_token: newRefreshToken
            })
        }

        if (grant_type === 'cookie_token') { // non standard grant_type
            if (!client_id) {
                return reply.code(400).send({error:'invalid_request', error_description:'client_id is required'})
            }
            const { session_token, refresh_token } = getCookies(req)
            if (!session_token && !refresh_token) {
                // no existing session
                const origin = { client_id }
                const { session_token, nonce } = await makeSessionToken( origin )
                if (!session_token) {
                    return reply.code(500).send({error:'server_error: session_token not created'})
                }
                if (!nonce) {
                    return reply.code(500).send({error:'server_error: nonce not created'})
                }
                setSessionCookie(reply, session_token )
                return reply.send({
                    loggedIn: false,
                    nonce
                })
            }

            // we have an existing session
            const newRefreshToken = (refresh_token)
                ? refreshFromRefresh(refresh_token)
                : await refreshFromSession(session_token)
            const newAccessToken = accessFromRefresh(newRefreshToken)
            reply.header('Set-Cookie', createTokenCookies( newAccessToken, newRefreshToken ))
            return reply.send({
                loggedIn: true
            })
        }

        if (grant_type === 'client_credentials') {
            return reply.code(501).send('Not Implemented')
        }
        reply.code(400).send({error:'unsupported_grant_type'})
    } catch (e) {
        const error = e as TokenError
        console.error('token endpoint fault',error)
        setSessionCookie(reply, '')
        return reply.code(error.statusCode || 500).send({error: 'token parsing'})
    }
}

const logoutEndpoint = async (req: FastifyRequest, reply: FastifyReply) => {
    const { nonce } = req.body as { nonce?: string }

    await logoutUser(nonce || '')
    setTokenCookies(reply, '', '')

    return reply.send({loggedOut: true})
}


const introspectEndpoint = async (req: FastifyRequest, reply: FastifyReply) => {
    let token: string = ''

    if (req.method === 'POST') {
        ({ token } = req?.body as { token: string })
    } else if (req.method === 'GET') {
        const cookies = getCookies(req)
        token = cookies?.access_token
    }

    if (!token) {
        return reply.code(400).send({error:'invalid_request', error_description:'token is required'})
    }
    if (!jws.verify(token, 'RS256', PUBLIC_KEY))
        return reply.send({active: false})
    const { payload } = jws.decode(token, { json: true }) || {} as jws.Signature
    if (!payload) {
        return reply.send({active: false})
    }
    const now = Math.floor(Date.now() / 1000)
    if (payload.exp < now) {
        return reply.send({active: false})
    }
    return reply.send({active: true, ...payload})
}

const loginSyncUrl = process.env.LOGIN_SYNC_URL

if (loginSyncUrl) {
    if (!(loginSyncUrl.startsWith('http://') || loginSyncUrl.startsWith('https://'))) {
        throw new Error('LOGIN_SYNC_URL must be a valid URL and start with https:// or http://')
    }
    console.log('loginSyncUrl', loginSyncUrl)
}

const logoutUser = async (nonce: string) => {
    const result = await state.remove(nonce)
}

const logoutSync = async (params: LogoutSyncParams): Promise<LogoutSyncResponse> => {

    try {
        const clearedCookies = createTokenCookies('', '')

        debugger
        
            console.log('logoutSync called x', clearedCookies)
        
            console.log('logoutSync get', params.cbRes)
            // console.log('logoutSync get', params.cbRes.getHeaders())
        // 
            params.cbRes.setHeader('Set-Cookie', clearedCookies)
        
            console.log('logoutSync postheaders', params.cbRes.getHeaders())
        
    } catch (e) {
        console.error('logoutSync error', e)
    }


    return null
}

const loginSync = async ( params: LoginSyncParams ): Promise<LoginSyncResponse> => {
    const { payload, token, target_uri } = params
    const { nonce, sub, aud } = payload

// TBD - move reading in state further up so that we can include state in call to loginSyncUrl

    const now = Math.floor(Date.now() / 1000)

    const currentState = await state.read(nonce)
    if (!currentState) {
        console.error({error:'invalid_request', error_description:'nonce is invalid'})
        return {}
    }
    if (currentState.loggedIn) {
        console.error({error:'invalid_request', error_description:'nonce is already logged in'})
        return {}
    }
    if ((currentState.exp ?? 0) < now) {
        console.error({error:'invalid_request', error_description:'state has expired'})
        return {}
    }

    // we have a valid state to change to sync login across channels
    // this is what we hope have in the access_token
    const statePayload: state.State = {
        loggedIn: true,
        iss: ISSUER,
        exp: now + STATE_LIFETIME,
        nonce,
        sub,
        aud,
    }

    if (currentState?.origin?.client_id) {
        statePayload.client_id = currentState.origin.client_id
    }

    // POTENTIAL FUTURE - reduce size of hello_auth cookie
    // this is what is returned from op=auth
    // cookie will contain updatedAuth + defaults of `isLoggedIn`, `sub`, and `iat`
    // const hello_auth: { updatedAuth: { app_sub?: string } } = { updatedAuth: {} }
 
    const syncResponse: LoginSyncResponse = {}
    if (loginSyncUrl) { // see if user is allowed to login
        const response = await fetch(loginSyncUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                payload, 
                token, 
                origin: {
                    client_id: currentState?.origin?.client_id,
                    target_uri
                }
            })
        })
        if (!response.ok) {
                console.log(`loginSyncUrl ${loginSyncUrl} returned ${response.status} - access denied for sub ${sub}`)
                await logoutUser(nonce)
                return { accessDenied: true }
        }
        // we have a 2xx response
        if ((response.status === 200) && (response.headers.get('content-type')?.includes('application/json'))) {
            try {
                const json = await response.json()
                const { accessDenied, payload, target_uri: new_target_uri }  = json                
                if (accessDenied) {
                    console.log('loginSync - access denied for sub', sub)
                    await logoutUser(nonce)
                    return { accessDenied: true}
                }
                if (payload) { 
                    if (payload.sub) {
                        statePayload.sub = payload.sub
                        statePayload.hello_sub = sub
                        // hello_auth.updatedAuth.app_sub = payload.sub // so op=auth has access to the app sub
                    }
                    if (payload.scope)
                        statePayload.scope = payload.scope
                    if (payload.client_id)
                        statePayload.client_id = payload.client_id
                }
                if (new_target_uri) {
                    // redirect to new_target_uri
                    syncResponse.target_uri = new_target_uri
                }
            } catch (e) {
                console.error('loginSync - JSON parsing error', e)
            }
        }

        // fall through to update state as access is granted
    }

    await state.update(nonce, statePayload)

    return syncResponse // we could minimize hello_auth cookie here by returning an object with updatedAuth
}


const helloConfig: HelloConfig = {
    clientId: process.env.CLIENT_ID || process.env.HELLO_CLIENT_ID,
    cookieSecret: process.env.COOKIE_SECRET || process.env.HELLO_COOKIE_SECRET,
    logConfig: true,
    apiRoute: AUTH_ROUTE,
    loginSync,
    logoutSync,
}

// console.log('api.js', {helloConfig})

const api = (app: FastifyInstance) => {
    app.register(formbody)
    app.register(helloAuth, helloConfig)
    app.get('/.well-known/oauth-authorization-server', (req, reply) => {
        return reply.send(META_DATA)
    })
    app.get('/', async (req, reply) => { // for dev and test
        const auth = await req.getAuth()
        return reply.send(auth)
    })
    app.post(TOKEN_ENDPOINT, tokenEndpoint)
    app.post(LOGOUT_ENDPOINT, logoutEndpoint)
    app.post(INTROSPECTION_ENDPOINT, introspectEndpoint)
    app.get(INTROSPECTION_ENDPOINT, introspectEndpoint)
    app.post(REVOCATION_ENDPOINT, (req, reply) => {
        return reply.code(501).send('Not Implemented')
    })
    app.get(JWKS_ENDPOINT, (req, reply) => {
        return reply.send(PUBLIC_JWKS)
    })
    app.get(AUTH_ROUTE+"/version", (req, reply) => {
        return reply.send({version});
    });
    if (!PRODUCTION) {
        // used to test if cookies are getting cleared
        app.get(TOKEN_ENDPOINT+"/cookies", (req, reply) => {
            return reply.send({cookies: getCookies(req)});
        });
    }
}

export { api, PORT, loginSync } // loginSync is exported for testing
