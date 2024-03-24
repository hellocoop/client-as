#!/bin/bash

if [ ! -f privateJWKS.json ]; then
    echo '{"keys": []}' > privateJWKS.json
fi

output=$(node rotate.mjs < privateJWKS.json)
echo "${output}" > privateJWKS.json