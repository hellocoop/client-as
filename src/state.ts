// store state of auth

import Redis from 'ioredis';
import { STATE_LIFETIME } from './constants';

let redis: Redis | undefined;

if (process.env.REDIS_URL) {
  redis = new Redis(process.env.REDIS_URL);
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