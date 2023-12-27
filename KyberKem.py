from os import urandom
import kyber_ietf


kemparams = kyber_ietf.params(k=6, du=11, dv=5, eta1=2)
# kemparams = kyber_ietf.params1024

if kemparams.k == 2:
    PUBLIC_KEY_BYTES = 800
    CIPHERTEXT_KEY_BYTES = 768

elif kemparams.k == 3:
    PUBLIC_KEY_BYTES = 1184
    CIPHERTEXT_KEY_BYTES = 1088

elif kemparams.k == 4:
    PUBLIC_KEY_BYTES = 1568
    CIPHERTEXT_KEY_BYTES = 1568

elif kemparams.k == 6:
    PUBLIC_KEY_BYTES = 2336
    CIPHERTEXT_KEY_BYTES = 2272

    # Redefine CBD so that eta1 and eta2 = 1.5
    cbd_min = 6
    cbd_max = 15 - cbd_min

    def CBD15(a, eta):
        assert len(a) == 64*eta
        b = kyber_ietf.WordsToBits(a, 8)
        cs = []
        for i in range(256):
            idx = b[0] + 2*b[1] + 4*b[2] + 8 * b[3]
            if idx < cbd_min:
                cs.append(1)
            elif idx > cbd_max:
                cs.append(3328)
            else:
                cs.append(0)
            b = b[2*eta:]
        return kyber_ietf.Poly(cs)
    kyber_ietf.CBD = CBD15


def keygen(seed=urandom(64)):
    return kyber_ietf.KeyGen(seed, kemparams)


def encode(pk, seed=urandom(32)):
    return kyber_ietf.Enc(pk, seed, kemparams)


def decode(sk, ct):
    return kyber_ietf.Dec(sk, ct, kemparams)


# oqs api
_sk = None


def generate_keypair(seed=urandom(64)):
    global _sk
    pk, sk = kyber_ietf.KeyGen(seed, kemparams)
    _sk = sk
    return pk


def encap_secret(pk, seed=urandom(32)):
    return kyber_ietf.Enc(pk, seed, kemparams)


def decap_secret(ct):
    global _sk
    return kyber_ietf.Dec(_sk, ct, kemparams)


details = {
    'length_public_key': PUBLIC_KEY_BYTES,
    'length_ciphertext': CIPHERTEXT_KEY_BYTES,
}

if __name__ == "__main__":
    from time import time
    seed1 = b'0123456701234567012345670123456701234567012345670123456701234567'
    seed2 = b'01234567012345670123456701234567'

    start = time()
    pk, sk = keygen(seed1)
    print('> ', time() - start, 'sec')
    start = time()
    ct, ss1 = encode(pk, seed2)
    print('> ', time() - start, 'sec')
    start = time()

    print(len(pk), len(ct), len(sk))
    print(ss1)
    # ct = b'0' + ct[1:]

    ss2 = decode(sk, ct)
    print('> ', time() - start, 'sec')
    print(ss2)

    assert (len(pk) == PUBLIC_KEY_BYTES)
    assert (len(ct) == CIPHERTEXT_KEY_BYTES)
