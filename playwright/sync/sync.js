
const fastify = require('fastify')({ logger: false });

let lastSyncValue = null;
const defaultMockValues = { code: 200, response: {} };
let mockValues = { ...defaultMockValues }

function isDefaultMockValues() {
    return JSON.stringify(mockValues) === JSON.stringify(defaultMockValues);
}

// GET /sync -- get what was lasted posted
fastify.get('/sync', async (request, reply) => {
  return lastSyncValue;
});

// DELETE /sync -- clear the last posted value
fastify.delete('/sync', async (request, reply) => {
  lastSyncValue = null;
  return lastSyncValue;
});

// POST /sync -- this is the actual call being mocked
fastify.post('/sync', async (request, reply) => {
  lastSyncValue = request.body
  if (isDefaultMockValues()) {
        return reply.code(200).send({});
    }
    return reply.code(mockValues.code).send(mockValues.response);
});

// GET /mock -- get the current mock values
fastify.get('/mock', async (request, reply) => {
  return mockValues;
});

// POST /mock -- set what will be mocked
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
