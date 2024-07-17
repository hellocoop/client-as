// constants

export const API_ROOT = process.env.API_ROOT || '/api'
export const AUTH_ROUTE = process.env.HELLO_AUTH_ROUTE || '/api/auth'
export const TOKEN_ENDPOINT = AUTH_ROUTE + '/token'
export const LOGOUT_ENDPOINT = AUTH_ROUTE + '/logout'
export const REVOCATION_ENDPOINT = AUTH_ROUTE + '/revoke'
export const JWKS_ENDPOINT = AUTH_ROUTE + '/jwks'
export const INTROSPECTION_ENDPOINT = AUTH_ROUTE + '/introspect'

export const ACCESS_LIFETIME = 5 * 60              // 5 minutes
export const STATE_LIFETIME = 5 * 60               // 5 minutes
export const REFRESH_LIFETIME = 30 * 24 * 60 * 60  // 30 days
export const DPOP_LIFETIME = 60                    // 1 minute for clock skew
