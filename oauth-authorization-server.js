


return {
    issuer: ``,
    authorization_endpoint: ``,
    jwks_uri: ``,
    grant_types_supported: [
        'authorization_code', 
        'client_credentials', 
        'refresh_token',
        'cookie_token', // non-standard
    ],
    revocation_endpoint: ``,
    dpop_signing_alg_values_supported: [
        'RS256'
    ],
}