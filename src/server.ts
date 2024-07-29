// index.ts

import { api, PORT } from './api'
import Fastify, { FastifyInstance } from 'fastify'
import * as logger from './logger';

const app: FastifyInstance = Fastify()

api(app)

app.listen({ host: '0.0.0.0', port: PORT }, function (err, address) {
    if (err) {
      console.error(err);
      process.exit(1);
    }
    logger.info(`server listening on ${address}`);
})