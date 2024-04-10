
const key = 
`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCMaJVmGtHyibF1Gylqgi1ghl4O1wvcVif+3LneNAcpO0zXFGKz
uPRaKXPaJYNxtii96TcUH1iB2Im0QQwEl5voY4Czi1AzxDWc3/i+fjGYY0La6c1C
P0vIfkvUj8odc592R3BuCfFxuH0s6KCpKPdzihoMZ75PpRfp2otvpmP3+wIDAQAB
AoGAdP+IzkY2/9VA7AYwIrJKwY31voPvPDEGrtaags/zz6W8R9SS0pOh+adlBDgS
KaTSmj1FSh08kSYwyOUS8Jisrl69nwvm543zVwYKqd7TP8SvEKppyv/uZepA1HP4
9wG7YU7UY4aiyQ/BshNE+r7Y0ec6XQGrVKvW23V6ydMtHlECQQDdimKfKB3Kfk8h
HJm/z1KZKBzyKA1I0K0LAZcss0NssV44LfwUXD2qnZA9Fl1jEENJiqAeXl7RWE7g
8HmcgZr3AkEAoj+RhbzxwOyLAijFPxrww0Gijj41qGw1zVHz3C1xNHS9tzI7ree1
tNlP+S8LIRnvWEnft/B2rTxekQ6hewFmHQJAP3oZS/UYpB6Q2bHyM81Zo1yk/pWP
SN/R1Sd9g2dR2GDx2DME2WicmrhOzdIMrAfK39WCj3EGxgEBiN4eWkOgfQJAQl4u
cL5xRbF8y01SIhYrFjPrArR/zn01JN+5GP+dpw95604pC2IU+f1KsWuE6e1p8nuF
gABlC0f+huetNlvEIQJBANp0FBikYhLoKrwuvLjLoq1+qZeoKLDPC2BLSdSB5LZK
netQz9NUtlY2bGfKbRPH7iFYsprhK02VxsY0SglCqCU=
-----END RSA PRIVATE KEY-----`






BELOW CODE IS GENERATED AN DNOT REVIEWED !!!!!






import * as dotenv from 'dotenv';
dotenv.config({ path: 'tests/.env' }); // Adjust the path as necessary
import assert from 'assert';
import Fastify, { FastifyInstance, LightMyRequestResponse } from 'fastify';

import { api } from '../src/api';
import { TOKEN_ENDPOINT } from '../src/constants'

let app: FastifyInstance;

before(async () => {
  app = Fastify();
  app.register(api);
  await app.ready();
});

after(() => {
  app.close();
});

describe('tokenExchange', () => {
  it('should return an error when requested_token_type is not urn:ietf:params:oauth:token-type:access_token', async () => {
    const response: LightMyRequestResponse = await app.inject({
      method: 'POST',
      url: TOKEN_ENDPOINT,
      payload: {
        requested_token_type: 'invalidRequestedTokenType',
        subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
        subject_token: 'validSubjectToken',
      }
    });

    assert.strictEqual(response.statusCode, 400);
    assert.strictEqual(response.json().error, 'invalid_request');
    assert.strictEqual(response.json().error_description, 'requested_token_type must be urn:ietf:params:oauth:token-type:access_token');
  });

  it('should return an error when subject_token_type is not urn:ietf:params:oauth:token-type:jwt', async () => {
    const response: LightMyRequestResponse = await app.inject({
      method: 'POST',
      url: TOKEN_ENDPOINT,
      payload: {
        requested_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        subject_token_type: 'invalidSubjectTokenType',
        subject_token: 'validSubjectToken',
      }
    });

    assert.strictEqual(response.statusCode, 400);
    assert.strictEqual(response.json().error, 'invalid_request');
    assert.strictEqual(response.json().error_description, 'subject_token_type must be urn:ietf:params:oauth:token-type:jwt');
  });

  it('should return an error when subject_token is not provided', async () => {
    const response: LightMyRequestResponse = await app.inject({
      method: 'POST',
      url: TOKEN_ENDPOINT,
      payload: {
        requested_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
      }
    });

    assert.strictEqual(response.statusCode, 400);
    assert.strictEqual(response.json().error, 'invalid_request');
    assert.strictEqual(response.json().error_description, 'subject_token is required');
  });

  // Add similar tests for other checks in the tokenExchange function
});