// store state of auth 

import Redis from 'ioredis';
import { STATE_LIFETIME } from './constants';

let redis: Redis | undefined;

if (process.env.REDIS_URL) {
  redis = new Redis(process.env.REDIS_URL);
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