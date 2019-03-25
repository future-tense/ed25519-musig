
import test from 'ava';
import * as ed25519 from '../lib/elliptic/ed25519';
import * as musig from '../lib';


test('2-of-2 key aggregation', t => {

    //  set-up: participants generate Keypairs and submit their public keys
    const keys1 = ed25519.Keypair.random();
    const keys2 = ed25519.Keypair.random();

    const config = new musig.Config([
        keys1.publicKey,
        keys2.publicKey
    ]);

    const publicKey = config.publicKey;

    const message = Buffer.from('fshgeytfsdyydtrsred');
    const session1 = new musig.Session(config, keys1.secretKey, message);
    const session2 = new musig.Session(config, keys2.secretKey, message);

    //  signing round #1: generate random nonces, and submit commitments
    const c1 = session1.getLocalCommitment();
    const c2 = session2.getLocalCommitment();
    session1.setRemoteCommitment(...c2);
    session2.setRemoteCommitment(...c1);

    //  signing round #2: submit nonces
    const n1 = session1.getLocalNonce();
    const n2 = session2.getLocalNonce();
    session1.setRemoteNonce(...n2);
    session2.setRemoteNonce(...n1);

    //  signing round #3: sign message and submit signature for aggregation
    const s1 = session1.getLocalSignature();
    const s2 = session2.getLocalSignature();
    session1.setRemoteSignature(...s2);
    session2.setRemoteSignature(...s1);

    //  verify signature
    const signature = session1.aggregateSignature;
    const vk = ed25519.VerificationKey.fromPublicKey(publicKey);
    t.true(vk.verify(signature, message));
});
