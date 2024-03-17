// index.ts

import { api, PORT } from './api'
import Fastify, { FastifyInstance } from 'fastify'

const app: FastifyInstance = Fastify()

api(app)

app.listen({ port: PORT }, function (err, address) {
    if (err) {
      console.error(err);
      process.exit(1);
    }
    console.log(`server listening on ${address}`);
})