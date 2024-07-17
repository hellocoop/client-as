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

type BaseState = {
  iss: string,
  exp: number,
  nonce: string,
}

type Origin = {
  client_id: string,
  target_uri?: string,
}

type LoggedOutState = {
  loggedIn: false,
  origin?: Origin,
}

type LoggedInState = {
  loggedIn: true,
  aud: string,
  sub: string,
  code_used?: number,
  hello_sub?: string,
  scope?: string,
  client_id?: string,
}


type State = BaseState & (LoggedOutState | LoggedInState);

// for development! ... in production, use redis
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
    await redis.set(key, JSON.stringify(value), 'EX', STATE_LIFETIME);
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

const remove = async (key: string): Promise<void> => {
  if (redis) {
    await redis.del(key);
  } else {
    delete state[key];
  }
}

export { create, read, update, remove, State, Origin };