// constants

export const TOKEN_ENDPOINT = '/token'
export const REVOCATION_ENDPOINT = '/revoke'
export const JWKS_ENDPOINT = '/jwks'
export const LOGIN_ENDPOINT = '/login'

export const ACCESS_LIFETIME = 5 * 60              // 5 minutes
export const STATE_LIFETIME = 5 * 60               // 5 minutes
export const REFRESH_LIFETIME = 30 * 24 * 60 * 60  // 30 days
export const DPOP_LIFETIME = 60                    // 1 minute for clock skew