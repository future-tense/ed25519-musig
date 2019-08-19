
/**
 * The Edwards digital signing algorithm, using the "ed25519" curve
 */

import { eddsa as Eddsa} from 'elliptic';
import * as secureRandom from 'secure-random';

const ec = new Eddsa('ed25519');

type Scalar = typeof ec.curve.n;

/**
 * A pair of public and private ed25519 keys
 */

export class Keypair {

    public readonly scalar: Scalar;
    public readonly publicKey: Buffer;
    public readonly secretKey: Buffer;

    /**
     *
     * @param seed
     */
    private constructor(
        seed: Buffer
    ) {
        const key = ec.keyFromSecret(seed);
        this.publicKey = Buffer.from(key.getPublic());
        this.secretKey = seed;
        this.scalar = key.priv();
    }

    /**
     * Sign a message
     * @param message
     */
    public sign(
        message: Buffer
    ): Buffer {
        const key = ec.keyFromSecret(this.secretKey);
        key._pubBytes = Array.from(this.publicKey);
        return Buffer.from(key.sign(message).toBytes());
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
        return ec.verify(
            message,
            Array.from(signature),
            Array.from(this.publicKey)
        );
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
        return ec.verify(
            message,
            Array.from(signature),
            Array.from(this.publicKey)
        );
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
