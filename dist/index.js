"use strict";
// index.ts
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const api_1 = require("./api");
const fastify_1 = __importDefault(require("fastify"));
const app = (0, fastify_1.default)();
(0, api_1.api)(app);
app.listen({ port: api_1.PORT }, function (err, address) {
    if (err) {
        console.error(err);
        process.exit(1);
    }
    console.log(`server listening on ${address}`);
});
