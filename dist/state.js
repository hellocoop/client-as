"use strict";
// session 
Object.defineProperty(exports, "__esModule", { value: true });
exports.update = exports.read = exports.create = void 0;
const state = {};
const read = async (key) => {
    return state[key];
};
exports.read = read;
const create = async (key, value) => {
    state[key] = value;
    return;
};
exports.create = create;
const update = async (key, value) => {
    state[key] = value;
    return;
};
exports.update = update;
