// session 

// hack for dev

// connect to Redis server

// use exp to set the expiration time for the key

type State = {
  loggedIn: boolean,
  nonce: string,
  exp: number,
  iss: string,
  aud?: string,
  sub?: string,
  code_used?: number
}

const state: Record<string, State> = {};

const read = async (key: string): Promise<State | undefined> => {
return state[key];
}

const create = async (key: string, value: State): Promise<void> => {
  state[key] = value;
  return;
}

const update = async (key: string, value: State): Promise<void> => {
state[key] = value;
return;
}

export { create, read, update, State };
