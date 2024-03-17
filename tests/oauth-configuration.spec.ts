import assert from 'assert';
import Fastify, { FastifyInstance } from 'fastify';

import { api } from '../src/api';

describe('OAuth Configuration', () => {
    let app: FastifyInstance;
    
    before(async () => {
        app = Fastify();
        api(app);
    });
    
    it('should return issuer', async () => {
        const response = await app.inject({
            method: 'GET',
            url: '/.well-known/oauth-authorization-server'
        });
    
        // Using assert.strictEqual to check for equality
        assert.strictEqual(response.statusCode, 200, 'Status code is not 200');
        
        const { issuer } = response.json();
        // Asserting that the issuer matches the expected value
        assert.strictEqual(issuer, 'http://localhost:3000', 'Issuer does not match');
    });
});
