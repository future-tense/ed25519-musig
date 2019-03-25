
import * as elliptic from './elliptic/musig';

let hasDalek = false;
try {
    hasDalek = require('ed25519-dalek');
} catch (err) {}

const musig = hasDalek ? require('./dalek/musig') : elliptic;
const { Config, Session, Round } = musig;

export {
    Config,
    Session,
    Round
}
