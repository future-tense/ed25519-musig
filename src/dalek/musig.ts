
import { scalar, edwards }  from '@futuretense/ed25519-dalek';
import { sha512 as hash, sha256 } from '../hash';
import { Keypair, VerificationKey } from './ed25519';

const basepoint = edwards.basepoint;

export enum Round {
    commitment = 0,
    nonce = 1,
    signature = 2,
    finished = 3
}

export class Config {

    keys: Set<string>;
    vk: Map<string, VerificationKey>;
    numKeys: number;

    public _publicKey: Buffer;
    private _musig: Map<string, Buffer>;

    public constructor(publicKeys: Buffer[]) {

        this._musig = new Map<string, Buffer>();
        this.vk = new Map<string, VerificationKey>();

        this.keys = new Set<string>(publicKeys.map(x => x.toString('hex')));

        const l = hash(Array.from(this.keys).sort());

        const points: Buffer[] = [];
        for (const key of this.keys) {
            const keyBuf = Buffer.from(key, 'hex');
            this.vk.set(key, VerificationKey.fromPublicKey(keyBuf));

            const sb = scalar.fromHash(l, keyBuf);
            const point = edwards.scalarMult(sb, keyBuf);
            this._musig.set(key, sb);
            points.push(point);
        }

        this.numKeys = this.keys.size;
        this._publicKey = edwards.sum(points);
    }

    get publicKey() {
        return this._publicKey;
    }

    public musig(key: string): Buffer {
        return this._musig.get(key) as Buffer;
    }
}

export class Session {

    config: Config;
    kp: Keypair;
    message: Buffer;
    nonceKeys: Keypair;
    numKeys: number;
    round: Round;

    private commitment: Map<string, Buffer>;
    private signature: Map<string, Buffer>;
    private _nonce: Map<string, Buffer>;
    private challenge: Buffer;

    public aggregateNonce: Buffer;
    public aggregateSignature: Buffer;

    public constructor(config: Config, seed: Buffer, message: Buffer) {
        this.config = config;
        this.kp = Keypair.fromSeed(seed);
        this.message = message;

        this.nonceKeys = Keypair.random();

        this.commitment = new Map<string, Buffer>();
        this.signature = new Map<string, Buffer>();
        this._nonce = new Map<string, Buffer>();

        this.numKeys = config.numKeys;
        this.round = Round.commitment;
    }

    public nonce(key: string): Buffer {
        return this._nonce.get(key) as Buffer;
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

        this._nonce.set(key, nonce);
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
        return edwards.sum(nonces);
    }

    private getChallenge(): Buffer {
        return scalar.fromHash(
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

        return scalar.add(
            scalar.mult(
                scalar.mult(a, e),
                this.kp.scalar
            ),
            this.nonceKeys.scalar
        );
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

        const ae = scalar.mult(a, e);
        const res = edwards.addPoints(
            edwards.scalarMult(ae, keyBuf),
            this.nonce(key)
        );

        const s = edwards.scalarMult(signature, basepoint);
        return s.equals(res);
    }

    private setSignature(key: string, signature: Buffer) {
        if (this.round !== Round.signature) {
            throw 'Not enough nonces set yet!';
        }

        this.signature.set(key, signature);
        this._nonce.delete(key);

        if (this.signature.size === this.numKeys) {
            delete this._nonce;
            this.aggregateSignature = this.getAggregateSignature();
            this.round = Round.finished;
        }
    }

    private getAggregateSignature() {

        const sigs = Array.from(this.signature.values());
        const sum = scalar.sum(sigs);
        delete this.signature;

        return Buffer.concat([
            this.aggregateNonce,
            sum
        ]);
    }
}
