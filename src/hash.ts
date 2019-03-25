
import { sha256 as _sha256 } from 'js-sha256';
import { sha512 as _sha512 } from 'js-sha512';

export function sha256(...args): Buffer {
    const message = Buffer.concat(args.map(arg => Buffer.from(arg)));
    const hash = _sha256.array(message);
    return Buffer.from(hash);
}

export function sha512(...args): Buffer {
    const message = Buffer.concat(args.map(arg => Buffer.from(arg)));
    const hash = _sha512.array(message);
    return Buffer.from(hash);
}
