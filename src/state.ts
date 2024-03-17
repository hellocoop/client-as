// session 

// hack for dev

// connect to Redis server

type State = {
    loggedIn: boolean,
    nonce: string,
    exp: number,
    iss: string,
    sub?: string,
}

const state = {}


const read = async (key): Promise<State> => {
  return state[key]
}

const create = async (key, value): Promise<any> => {
    state[key] = value
    return
}

const update = async (key, value): Promise<any> => {
  state[key] = value
  return
}

export { create, read, update, State }