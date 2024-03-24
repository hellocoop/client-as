# Key Directory

This directory MUST contain a file named `privateJWKS.json` that is of the JWKS format that has one or more JWKs. The public keys will be exposed as the jwks_uri for the authorization server. The first key will be used to sign new access tokens and refresh tokens. The `rotate.mjs` node script will read in an existing `privateJWKS.json` file and prepend a new key to the list. It will remove keys from the end to keep the length to a maximum of 3 keys.

See `rotate.sh` for how to use `rotate.mjs` for running against a production `privateJWKS.json` file.

For development and testing, the built image will have a generated `privateJWKS.json` in this directory

For production, this path can be bound to the production `keys` directory that contains a `privateJWKS.json` file. 