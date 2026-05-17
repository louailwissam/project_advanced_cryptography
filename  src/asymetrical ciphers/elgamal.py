from sympy import isprime, primitive_root
import random
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto_base import AlgorithmeCryptographique


class ElGamal(AlgorithmeCryptographique):

    def __init__(self, bits: int = 512):
        self.bits = bits
        self.p = None   # grand premier (safe prime)
        self.g = None   # générateur primitif
        self.x = None   # clé privée
        self.y = None   # clé publique y = g^x mod p
        self._generer_cles()
    @staticmethod
    def _generer_safe_prime(bits: int) -> int:
        while True:
            # Générer q premier de (bits-1) bits
            debut = 2 ** (bits - 2)
            q = random.randint(debut, 2 * debut) | 1   # impair
            # Chercher le prochain q premier, puis vérifier p = 2q+1
            while True:
                if isprime(q):
                    p = 2 * q + 1
                    if isprime(p):
                        return p
                q += 2   

    def _generer_cles(self):
        print(
            f"[ElGamal] Génération des paramètres ({self.bits} bits)...",
            end=" ", flush=True)
        self.p = self._generer_safe_prime(self.bits)
        self.g = int(primitive_root(self.p))   
        self.x = random.randint(2, self.p - 2)
        self.y = pow(self.g, self.x, self.p)

        print("OK")
        print(f"  p ({self.p.bit_length()} bits), g = {self.g}")
        print(f"  Clé privée x (secrète), Clé publique y = g^x mod p\n")

    def chiffrer(self, M, cle=None) -> tuple:
        if not (0 < M < self.p):
            raise ValueError(f"M doit satisfaire 0 < M < p = {self.p}")
        k = random.randint(2, self.p - 2)
        C1 = pow(self.g, k, self.p)
        C2 = (M * pow(self.y, k, self.p)) % self.p
        return C1, C2
    def dechiffrer(self, chiffre, cle=None) -> int:
        C1, C2 = chiffre
        s = pow(C1, self.x, self.p)            
        s_inv = pow(s, self.p - 2, self.p)    
        return (C2 * s_inv) % self.p

def demo_chiffrement(eg: ElGamal):
    M = 12345
    print("=" * 65)
    print("ElGamal sur M = 12345")
    print("=" * 65)

    C1 = eg.chiffrer(M)
    C2 = eg.chiffrer(M)

    print(f"Chiffrement 1 : C1={C1[0] % 10**10}..., C2={C1[1] % 10**10}...")
    print(f"Chiffrement 2 : C1={C2[0] % 10**10}..., C2={C2[1] % 10**10}...")
    print(f"\nNon-déterminisme — Même M → chiffrés différents : {C1 != C2}")

    D1 = eg.dechiffrer(C1)
    D2 = eg.dechiffrer(C2)
    print(f"\nDéchiffrement 1 : M = {D1} {'OK' if D1 == M else 'ERREUR'}")
    print(f"Déchiffrement 2 : M = {D2} {'OK' if D2 == M else 'ERREUR'}")
    print(f"Propriété D(E(M)) = M : {D1 == M and D2 == M}")


def demo_malleabilite(eg: ElGamal):
    M = 12345
    C = eg.chiffrer(M)
    C1, C2 = C

    C2_forge = (2 * C2) % eg.p
    C_forge = (C1, C2_forge)

    M_forge = eg.dechiffrer(C_forge)
    attendu = (2 * M) % eg.p

    print(" MALLÉABILITÉ ElGamal — Forger E(2M) depuis E(M)")
    print(f"Message original  M    = {M}")
    print(f"Chiffré original  C    = (C1, C2)")
    print(f"Chiffré forgé     C'   = (C1, 2·C2 mod p)")
    print(f"Déchiffrement de C'    = {M_forge}")
    print(f"Attendu : 2·M mod p    = {attendu}")
    print(f"Forgerie réussie       : {M_forge == attendu}")
    print("\nOn a chiffré 2M sans connaître M ni la clé privée x.")


if __name__ == "__main__":
    eg = ElGamal(bits=512)

    print("\nPARTIE 2 : Démonstration M=12345")
    demo_chiffrement(eg)

    print("\nPARTIE 3 : Malléabilité")
    demo_malleabilite(eg)