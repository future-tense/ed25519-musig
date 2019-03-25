
/**
 * The Edwards digital signing algorithm, using the "ed25519" curve
 */

import { ed25519 } from '@futuretense/ed25519-dalek';
import * as secureRandom from 'secure-random';
import { sha512 } from 'js-sha512';

/**
 * A pair of public and private ed25519 keys
 */

export class Keypair {

    public readonly scalar: Buffer;
    public readonly publicKey: Buffer;
    public readonly secretKey: Buffer;

    /**
     *
     * @param seed
     */
    private constructor(
        seed: Buffer
    ) {
        const hash = sha512.array(seed);
        hash[0]  &= 0xf8;
        hash[31] &= 0x3f;
        hash[31] |= 0x40;
        this.scalar = Buffer.from(hash.slice(0, 32));
        this.publicKey = ed25519.generatePublicKey(seed);
        this.secretKey = seed;
    }

    /**
     * Sign a message
     * @param message
     */
    public sign(
        message: Buffer
    ): Buffer {
        return ed25519.sign(this.secretKey, this.publicKey, message);
    }

    /**
     * Verify a signed message
     * @param signature
     * @param message
     */
    public verify(
        signature: Buffer,
        message: Buffer
    ): boolean {
        return ed25519.verify(this.publicKey, message, signature);
    }

    /**
     * Generate a random keypair
     */
    static random(): Keypair {
        const sk = secureRandom(32, {type: 'Buffer'});
        return new Keypair(sk);
    }

    static fromSeed(seed): Keypair {
        return new Keypair(seed);
    }
}

/**
 *  A verification key is a public key that can only be used
 *  for verifying a transaction signed with its corresponding private key
 */

export class VerificationKey {

    readonly publicKey: Buffer;

    /**
     *
     * @param key
     */
    private constructor(
        key: Buffer
    ) {
        this.publicKey = key;
    }

    /**
     * Verify a signed message
     * @param signature
     * @param message
     */
    public verify(
        signature: Buffer,
        message: Buffer
    ): boolean {
        return ed25519.verify(this.publicKey, message, signature);
    }

    /**
     *
     * @param pk
     */
    public static fromPublicKey(
        pk: Buffer
    ): VerificationKey {
        return new VerificationKey(pk);
    }
}
