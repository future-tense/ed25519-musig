
import { eddsa } from 'elliptic';
import { sha512 as hash, sha256 } from '../hash';
import { Keypair, VerificationKey } from './ed25519';

const ec = new eddsa('ed25519');
const basepoint = ec.g;
const ell = ec.curve.n;

type Point = typeof basepoint;
type Scalar = typeof ell;

export const enum Round {
    commitment = 0,
    nonce = 1,
    signature = 2,
    finished = 3
}

export class Config {
    keys: Set<string>;
    vk: Map<string, VerificationKey>;
    numKeys: number;
    private _musig: Map<string, Scalar>;
    public _publicKey: Buffer;

    public constructor(publicKeys: Buffer[]) {

        this._musig = new Map<string, Scalar>();
        this.vk = new Map<string, VerificationKey>();
        this.keys = new Set<string>(publicKeys.map(x => x.toString('hex')));

        const l = hash(Array.from(this.keys).sort());

        const points: Buffer[] = [];
        for (const key of this.keys) {
            const keyBuf = Buffer.from(key, 'hex');
            this.vk.set(key, VerificationKey.fromPublicKey(keyBuf));
            const kp = ec.decodePoint(Array.from(keyBuf));
            const s = ec.hashInt(l, keyBuf);
            const point = kp.mul(s);
            this._musig.set(key, s);
            points.push(point);
        }

        this.numKeys = this.keys.size;
        this._publicKey = pointSumAsBuffer(points);
    }

    get publicKey() {
        return this._publicKey;
    }

    public musig(key: string): Scalar {
        return this._musig.get(key) as Scalar;
    }
}

/**
 *
 */

export class Session {

    config: Config;
    kp: Keypair;
    message: Buffer;
    nonceKeys: Keypair;
    numKeys: number;
    round: Round;

    private commitment: Map<string, Buffer>;
    private signature: Map<string, Scalar>;
    private _nonce: Map<string, Point>;
    private challenge: Scalar;

    public aggregateNonce: Buffer;
    public aggregateSignature: Buffer;

    public constructor(config: Config, seed: Buffer, message: Buffer) {

        this.config = config;
        this.kp = Keypair.fromSeed(seed);
        this.message = message;

        this.nonceKeys = Keypair.random();

        this.commitment = new Map<string, Buffer>();
        this.signature = new Map<string, Buffer>();
        this._nonce = new Map<string, Point>();

        this.numKeys = config.numKeys;
        this.round = Round.commitment;
    }

    public nonce(key: string): Point {
        return this._nonce.get(key) as Point;
    }

    public getLocalCommitment(): [Buffer, Buffer, Buffer] {

        const keyBuf = this.kp.publicKey;
        const key = keyBuf.toString('hex');
        const commitment = sha256(this.nonceKeys.publicKey);
        this.setCommitment(key, commitment);

        return [
            keyBuf,
            commitment,
            this.kp.sign(commitment)
        ];
    }

    public setRemoteCommitment(keyBuf: Buffer, data: Buffer, signature: Buffer) {

        const key = keyBuf.toString('hex');
        if (!this.config.keys.has(key)) {
            throw `Unknown key: ${key}`;
        }

        if (this.commitment.has(key)) {
            throw 'This commitment has already been set';
        }

        const vk = this.config.vk.get(key) as VerificationKey;
        if (!vk.verify(signature, data)) {
            throw 'Invalid signature';
        }

        this.setCommitment(key, data);
    }

    private setCommitment(key: string, commitment: Buffer) {
        if (this.round !== Round.commitment) {
            throw '';
        }

        this.commitment.set(key, commitment);
        if (this.commitment.size === this.numKeys) {
            this.round = Round.nonce;
        }
    }

    public getLocalNonce(): [Buffer, Buffer, Buffer] {

        const keyBuf = this.kp.publicKey;
        const key = keyBuf.toString('hex');
        const nonce = this.nonceKeys.publicKey;
        this.setNonce(key, nonce);

        return [
            keyBuf,
            nonce,
            this.kp.sign(nonce)
        ]
    }

    public setRemoteNonce(keyBuf: Buffer, nonce: Buffer, signature: Buffer) {

        const key = keyBuf.toString('hex');
        if (!this.config.keys.has(key)) {
            throw `Unknown key: ${key}`;
        }

        if (this._nonce.has(key.toString())) {
            throw 'This nonce has already been set';
        }

        const vk = this.config.vk.get(key) as VerificationKey;
        if (!vk.verify(signature, nonce)) {
            throw 'Invalid signature';
        }

        const commitment = this.commitment.get(key) as Buffer;
        if (!sha256(nonce).equals(commitment)) {
            throw 'This nonce doesn\'t match its commitment';
        }

        this.setNonce(key, nonce);
    }

    private setNonce(key: string, nonce: Buffer) {
        if (this.round !== Round.nonce) {
            throw 'Not enough commitments set yet!';
        }

        const point = ec.decodePoint(Array.from(nonce));
        this._nonce.set(key, point);
        this.commitment.delete(key);

        if (this._nonce.size === this.numKeys) {
            delete this.commitment;
            this.aggregateNonce = this.getAggregateNonce();
            this.challenge = this.getChallenge();
            this.round = Round.signature;
        }
    }

    private getAggregateNonce(): Buffer {
        const nonces = Array.from(this._nonce.values());
        return pointSumAsBuffer(nonces);
    }

    private getChallenge(): Scalar {
        return ec.hashInt(
            this.aggregateNonce,
            this.config._publicKey,
            this.message
        );
    }

    public getLocalSignature(): [Buffer, Buffer] {

        const keyBuf = this.kp.publicKey;
        const key = keyBuf.toString('hex');
        const sig = this.signPartial();
        this.setSignature(key, sig);

        return [
            keyBuf,
            sig
        ];
    }

    private signPartial(): Buffer {

        const key = this.kp.publicKey.toString('hex');
        const a = this.config.musig(key);
        const e = this.challenge;

        const sig = a.mul(e).umod(ell)
            .mul(this.kp.scalar).umod(ell)
            .add(this.nonceKeys.scalar).umod(ell);

        return Buffer.from(ec.encodeInt(sig));
    }

    public setRemoteSignature(keyBuf: Buffer, signature: Buffer) {

        const key = keyBuf.toString('hex');
        if (!this.config.keys.has(key)) {
            throw `Unknown key: ${key}`;
        }

        if (this.signature.has(key)) {
            throw 'This signature has already been set';
        }

        if (!this.verifyPartial(keyBuf, signature)) {
            throw 'Invalid signature';
        }

        this.setSignature(key, signature);
    }

    private verifyPartial(keyBuf: Buffer, signature: Buffer): boolean {

        const key = keyBuf.toString('hex');
        const a = this.config.musig(key);
        const e = this.challenge;

        const ae = a.mul(e).umod(ell);
        const kp = ec.decodePoint(Array.from(keyBuf));
        const nonce = this.nonce(key);
        const res = kp.mul(ae).add(nonce);

        const s = ec.decodeInt(Array.from(signature));
        const sp = basepoint.mul(s);
        return sp.eq(res);
    }

    private setSignature(key: string, signature: Buffer) {
        if (this.round !== Round.signature) {
            throw 'Not enough nonces set yet!';
        }

        const sig = ec.decodeInt(Array.from(signature));
        this.signature.set(key, sig);
        this._nonce.delete(key);

        if (this.signature.size === this.numKeys) {
            delete this._nonce;
            this.aggregateSignature = this.getAggregateSignature();
            this.round = Round.finished;
        }
    }

    private getAggregateSignature() {

        const sigs = Array.from(this.signature.values());
        const sum = scalarSumAsBuffer(sigs);
        delete this.signature;

        return Buffer.concat([
            this.aggregateNonce,
            sum
        ]);
    }
}

const pointSumAsBuffer = (points: Point[]): Point => {
    let sum = points[0];
    for (const point of points.slice(1)) {
        sum = sum.add(point);
    }

    return Buffer.from(ec.encodePoint(sum));
};

const scalarSumAsBuffer = (scalars: Scalar[]): Scalar => {
    let sum = scalars[0];
    for (const scalar of scalars.slice(1)) {
        sum = sum.add(scalar).umod(ell);
    }

    return Buffer.from(ec.encodeInt(sum));
};
