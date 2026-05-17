from sympy import nextprime, primitive_root
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dsa, ec
import sys
import os
import hashlib
import random
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto_base import AlgorithmeCryptographique
# exercice 1 signature RSA


class SignatureRSA(AlgorithmeCryptographique):
    def __init__(self, key_size: int = 2048):
        self.cle_privee = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
        )
        self.cle_publique = self.cle_privee.public_key()
        print(f"Cle RSA-{key_size} generee.")

    def chiffrer(self, texte_clair, cle=None):
        raise NotImplementedError("pas de chiffreement ")

    def dechiffrer(self, texte_chiffre, cle=None):
        raise NotImplementedError("pas de dechiffrement ")

    # signature avec le padding PKCS#1(apres hachage)
    def signer_pkcs(self, message: bytes) -> bytes:
        return self.cle_privee.sign(message, padding.PKCS1v15(), hashes.SHA256())
    # verifier la signature

    def verifier_pkcs(self, message: bytes, signature: bytes) -> bool:
        try:
            self.cle_publique.verify(
                signature, message, padding.PKCS1v15(), hashes.SHA256())
            return True
        except Exception:
            return False

    # signature avec pss
    def signer_pss(self, message: bytes) -> bytes:
        return self.cle_privee.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    # verification

    def verifier_pss(self, message: bytes, signature: bytes) -> bool:
        try:
            self.cle_publique.verify(
                signature, message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def demo(self):
        print(" exercice 5.1 — Signature RSA : PKCS#1 v1.5 vs PSS")
        msg = b"Message authentique signe par RSA."

        # PKCS#1 v1.5
        sig1a = self.signer_pkcs(msg)
        sig1b = self.signer_pkcs(msg)
        ok1 = self.verifier_pkcs(msg, sig1a)
        print(f"\n  PKCS#1 v1.5 :")
        print(f"Signature ({len(sig1a)} octets) : {sig1a[:16].hex()}...")
        print(f"Deterministe (sig1==sig2) : {sig1a == sig1b}")
        print(
            f"Verification (message original)  : {'pas derreur' if ok1 else 'echec'}")
        print(f"Verification (message altere)    : "
              f"{'echec' if not self.verifier_pkcs(b'Message modifie.', sig1a) else 'pas derreur'}")

        # PSS
        sig2a = self.signer_pss(msg)
        sig2b = self.signer_pss(msg)
        ok2 = self.verifier_pss(msg, sig2a)
        print(f"\n PSS :")
        print(f"Signature ({len(sig2a)} octets) : {sig2a[:16].hex()}...")
        print(f"Probabiliste (sig1 ≠ sig2) : {sig2a != sig2b}")
        print(f"Verification (message original)  : {'OK' if ok2 else 'echec'}")
        print(f"Verification (message altere)    : "
              f"{'echec' if not self.verifier_pss(b'Message modifie.', sig2a) else 'ok'}")

# exercice 5.2


class SignatureElGamal(AlgorithmeCryptographique):
    def __init__(self, bits: int = 512):
        self.bits = bits
        debut = 2 ** (bits - 1)
        self.p = nextprime(random.randint(debut, 2 * debut))
        self.g = int(primitive_root(self.p))
        self.x = random.randint(2, self.p - 2)
        self.y = pow(self.g, self.x, self.p)
        print(f"elgamal signature Parametres {bits} bits generes.")

    def chiffrer(self, texte_clair, cle=None):
        raise NotImplementedError

    def dechiffrer(self, texte_chiffre, cle=None):
        raise NotImplementedError

    def _hash_msg(self, message: bytes) -> int:
        return int(hashlib.sha256(message).hexdigest(), 16) % (self.p - 1)

    def _pgcd(self, a, b):
        while b:
            a, b = b, a % b
        return a

    def _inv_mod(self, a, m) -> int:
        return pow(a, -1, m)
    # signature

    def signer(self, message: bytes):
        H = self._hash_msg(message)
        # Choisir k aleatoire avec pgcd(k, p-1) = 1
        while True:
            k = random.randint(2, self.p - 2)
            if self._pgcd(k, self.p - 1) == 1:
                break
        r = pow(self.g, k, self.p)
        k_inv = self._inv_mod(k, self.p - 1)
        s = (k_inv * (H - self.x * r)) % (self.p - 1)
        return r, s
   # verification de la signature

    def verifier(self, message: bytes, signature) -> bool:
        r, s = signature
        if not (0 < r < self.p):
            return False
        H = self._hash_msg(message)
        lhs = (pow(self.y, r, self.p) * pow(r, s, self.p)) % self.p
        rhs = pow(self.g, H, self.p)
        return lhs == rhs

    def demo(self):
        print("exercice 5.2: signature al-gamal")
        msg = b"Document signe avec ElGamal."
        sig = self.signer(msg)
        ok = self.verifier(msg, sig)
        ok_ko = self.verifier(b"Document altere.", sig)

        print(f"  Message   : {msg.decode()}")
        print(
            f"  Signature : (r={str(sig[0])[:20]}..., s={str(sig[1])[:20]}...)")
        print(
            f"\n  Verification (message original) : {'OK' if ok else 'ECHEC'}")
        print(
            f"  Verification (message altéré)   : {'ECHEC' if not ok_ko else 'OK'}")

        sig2 = self.signer(msg)
        print(f"\n  Non-deterministe (sig1 ≠ sig2) : {sig != sig2}")

# exercice 5.3 DSA ET ECDSA
# signature digitele


class SignatureDSA(AlgorithmeCryptographique):

    # Taille de cle : 2048 bits, parametre q de 256 bits.
    def __init__(self):
        self.cle_privee = dsa.generate_private_key(
            key_size=2048, backend=default_backend())
        self.cle_publique = self.cle_privee.public_key()
        print("Cle DSA-2048 generee.")

    def chiffrer(self, texte_clair, cle=None):
        raise NotImplementedError("DSA est une signature, pas un chiffrement.")

    def dechiffrer(self, texte_chiffre, cle=None):
        raise NotImplementedError

    def signer(self, message: bytes) -> bytes:
        return self.cle_privee.sign(message, hashes.SHA256())

    def verifier(self, message: bytes, signature: bytes) -> bool:
        try:
            self.cle_publique.verify(signature, message, hashes.SHA256())
            return True
        except Exception:
            return False

    def demo(self):
        print("exercice 5.3 Signature DSA-2048")
        msg = b"Contrat signe avec DSA."
        sig = self.signer(msg)
        ok = self.verifier(msg, sig)
        sig2 = self.signer(msg)
        print(f"  Signature ({len(sig)} octets) : {sig[:16].hex()}...")
        print(f"  Probabiliste (sig1 ≠ sig2) : {sig != sig2}")
        print(f"  Verification (original) : {'ok' if ok else 'echec'}")
        print(
            f"  Verification (altere)   : {'echec' if not self.verifier(b'Contrat modifie.', sig) else 'ok'}")


class SignatureECDSA(AlgorithmeCryptographique):
  # Taille de signature = 72 octets
    def __init__(self):
        self.cle_privee = generate_private_key(SECP256R1(), default_backend())
        self.cle_publique = self.cle_privee.public_key()
        print("Cle ECDSA P-256 generee.")

    def chiffrer(self, texte_clair, cle=None):
        raise NotImplementedError(
            "ECDSA est une signature, pas un chiffrement.")

    def dechiffrer(self, texte_chiffre, cle=None):
        raise NotImplementedError

    def signer(self, message: bytes) -> bytes:
        return self.cle_privee.sign(message, ec.ECDSA(hashes.SHA256()))

    def verifier(self, message: bytes, signature: bytes) -> bool:
        try:
            self.cle_publique.verify(
                signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def demo(self):
        print("  exercice 5.3 partie 2 — Signature ECDSA P-256")
        msg = b"Transaction signee avec ECDSA P-256."
        sig = self.signer(msg)
        ok = self.verifier(msg, sig)
        sig2 = self.signer(msg)
        print(f"  Signature ({len(sig)} octets) : {sig[:16].hex()}...")
        print(f"  Probabiliste (sig1 ≠ sig2) : {sig != sig2}")
        print(f"  Verification (original) : {'OK' if ok else 'ECHEC'}")
        print(
            f"  Verification (altere)   : {'ECHEC' if not self.verifier(b'Transaction modifiee.', sig) else 'OK'}")


if __name__ == "__main__":

    print("\nTP5 — EXERCICE 5.1 : Signature RSA ")
    SignatureRSA(2048).demo()

    print("\nTP5 — EXERCICE 5.2 : Signature ElGamal")
    SignatureElGamal(512).demo()

    print("\nTP5 — EXERCICE 5.3 : DSA et ECDSA")
    SignatureDSA().demo()
    SignatureECDSA().demo()
