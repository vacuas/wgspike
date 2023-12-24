# KEX API wrapper

import os

import ThreeBears_nist
import kyber_ietf
import oqs


class KexBear(ThreeBears_nist.Bear):
    def __init__(self, name, variance, d, cca):
        super(KexBear, self).__init__(name, variance, d, cca, useFec=True)
        self.PUBLIC_KEY_BYTES = 24 + d * 390
        self.PRIVATE_KEY_BYTES = 40
        self.CIPHERTEXT_KEY_BYTES = 137 + d * 390

    def keygen(self, sk=os.urandom(40)):
        pk = self.keypair(sk)
        return pk, sk

    def encode(self, pk, seed=os.urandom(32)):
        shared, ct = self.encapsulate(pk, seed)
        return ct, shared

    def decode(self, sk, ct):
        return self.decapsulate(sk, ct)


class PythonKyber:
    def __init__(self, k=4):
        self.kemparams = kyber_ietf.params(k=k, du=11, dv=5, eta1=2)
        self.PUBLIC_KEY_BYTES = 32 + 384 * self.kemparams.k
        self.CIPHERTEXT_KEY_BYTES = 160 + 352 * self.kemparams.k

        if k > 4:
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

    def keygen(self, seed=os.urandom(64)):
        return kyber_ietf.KeyGen(seed, self.kemparams)

    def encode(self, pk, seed=os.urandom(32)):
        return kyber_ietf.Enc(pk, seed, self.kemparams)

    def decode(self, sk, ct):
        return kyber_ietf.Dec(sk, ct, self.kemparams)


class OqsKem:
    def __init__(self, name):
        self.name = name
        ephem_kem = oqs.KeyEncapsulation(name)
        self.PUBLIC_KEY_BYTES = ephem_kem.details['length_public_key']
        self.CIPHERTEXT_KEY_BYTES = ephem_kem.details['length_ciphertext']

    def keygen(self):
        sk = oqs.KeyEncapsulation(self.name)
        pk = sk.generate_keypair()
        return pk, sk

    def encode(self, pk):
        return oqs.KeyEncapsulation(self.name).encap_secret(pk)

    def decode(self, sk, ct):
        return sk.decap_secret(ct)


if __name__ == "__main__":
    for name in oqs.get_supported_kem_mechanisms():
        print(name)
