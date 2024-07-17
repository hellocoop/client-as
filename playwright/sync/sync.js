
const fastify = require('fastify')({ logger: false });

let lastSyncValue = null;
const defaultMockValues = { code: 200, response: {} };
let mockValues = { ...defaultMockValues }

function isDefaultMockValues() {
    return JSON.stringify(mockValues) === JSON.stringify(defaultMockValues);
}

// GET /sync
fastify.get('/sync', async (request, reply) => {
  return lastSyncValue;
});

// DELETE /sync
fastify.delete('/sync', async (request, reply) => {
  lastSyncValue = null;
  return lastSyncValue;
});

// POST /sync
fastify.post('/sync', async (request, reply) => {
    if (isDefaultMockValues()) {
        lastSyncValue = request.body
        return reply.code(200).send({});
    }
    return reply.code(mockValues.code).send(mockValues.response);
});

// GET /mock
fastify.get('/mock', async (request, reply) => {
  return mockValues;
});

// POST /mock
fastify.post('/mock', async (request, reply) => {
  const { code, response } = request.body;
  if (!code) {
    return reply.code(400).send({ message: 'code required' })
  }
  if (typeof code !== 'number') {
    return reply.code(400).send({ message: 'code must be a number' })
  }
  mockValues = { code, response };
  return mockValues;
});

// DELETE /mock
fastify.delete('/mock', async (request, reply) => {
  mockValues = { ...defaultMockValues }
  return reply.code(200).send({});
});

const port = process.env.PORT || 8888;
const start = async () => {
  try {
    await fastify.listen({ port, host: '0.0.0.0' });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
