// store state of auth

import Redis, {Cluster} from 'ioredis';
import { STATE_LIFETIME } from './constants';

const redisConfig = {
  host: process.env.REDIS_HOST,
  port: +(process.env.REDIS_PORT || 6379),
  options: {
    username: process.env.REDIS_USERNAME,
    password: process.env.REDIS_PASSWORD,
    ...(process.env.REDIS_ENABLE_TLS === 'true') && {tls: {
        rejectUnauthorized: process.env.REDIS_CLUSTER !== 'true', // cert validation throwing error in cluster mode
      }}
  },
  isCluster: process.env.REDIS_CLUSTER === 'true',
};

let redis: Redis | Cluster | undefined;


if (process.env.REDIS_HOST) {
  if (redisConfig.isCluster) {
    redis = new Redis.Cluster([{host: redisConfig.host, port: redisConfig.port}], {redisOptions: redisConfig.options});
  } else {
    redis = new Redis({
        host: redisConfig.host,
        port: redisConfig.port,
        ...redisConfig.options
      }
    );
  }
}

type State = {
  loggedIn: boolean,
  nonce?: string,
  exp?: number,
  iss?: string,
  aud?: string,
  sub?: string,
  code_used?: number
}

const state: Record<string, State> = {};

const read = async (key: string): Promise<State | undefined> => {
  if (redis) {
    const value = await redis.get(key);
    return value ? JSON.parse(value) : undefined;
  } else {
    return state[key];
  }
}

const create = async (key: string, value: State): Promise<void> => {
  if (redis) {
    await redis.set(key, JSON.stringify(value));
  } else {
    state[key] = value;
  }
}

const update = async (key: string, value: State): Promise<void> => {
  if (redis) {
    await redis.set(key, JSON.stringify(value), 'EX', STATE_LIFETIME);
  } else {
    state[key] = value;
  }
}

export { create, read, update, State };