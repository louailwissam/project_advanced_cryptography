from sympy import isprime
import random
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto_base import AlgorithmeCryptographique


class ElGamal(AlgorithmeCryptographique):

    def __init__(self, bits: int = 512):
        self.bits = bits
        self.p = None
        self.g = None
        self.x = None
        self.y = None
        self._generer_cles()

    @staticmethod
    def _generer_safe_prime(bits: int) -> tuple:
        while True:
            debut = 2 ** (bits - 2)
            q = random.randint(debut, 2 * debut) | 1
            while True:
                if isprime(q):
                    p = 2 * q + 1
                    if isprime(p):
                        return p, q
                q += 2
    @staticmethod
    def _trouver_generateur(p: int, q: int) -> int:
        for g in range(2, p):
            if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
                return g

    def _generer_cles(self):
        print(f"[ElGamal] Génération des paramètres ({self.bits} bits)...",
              end=" ", flush=True)

        self.p, q      = self._generer_safe_prime(self.bits)
        self.g         = self._trouver_generateur(self.p, q)  
        self.x         = random.randint(2, self.p - 2)
        self.y         = pow(self.g, self.x, self.p)

        print("OK")
        print(f"  p ({self.p.bit_length()} bits), g = {self.g}")
        print(f"  Clé privée x (secrète), Clé publique y = g^x mod p\n")

    def chiffrer(self, M, cle=None) -> tuple:
        if not (0 < M < self.p):
            raise ValueError(f"M doit satisfaire 0 < M < p = {self.p}")
        k  = random.randint(2, self.p - 2)
        C1 = pow(self.g, k, self.p)
        C2 = (M * pow(self.y, k, self.p)) % self.p
        return C1, C2
    def dechiffrer(self, chiffre, cle=None) -> int:
        C1, C2 = chiffre
        s      = pow(C1, self.x, self.p)
        s_inv  = pow(s, self.p - 2, self.p)
        return (C2 * s_inv) % self.p

def demo_chiffrement(eg: ElGamal):
    M = 12345
    print("=" * 65)
    print("PARTIE 2 — ElGamal sur M = 12345")
    print("=" * 65)

    enc1 = eg.chiffrer(M)
    enc2 = eg.chiffrer(M)

    print(f"Chiffrement 1 : C1={enc1[0] % 10**10}..., C2={enc1[1] % 10**10}...")
    print(f"Chiffrement 2 : C1={enc2[0] % 10**10}..., C2={enc2[1] % 10**10}...")
    print(f"\nNon-déterminisme — Même M → chiffrés différents : {enc1 != enc2}")

    D1 = eg.dechiffrer(enc1)
    D2 = eg.dechiffrer(enc2)
    print(f"\nDéchiffrement 1 : M = {D1}  {'OK' if D1 == M else 'ERREUR'}")
    print(f"Déchiffrement 2 : M = {D2}  {' OK' if D2 == M else 'ERREUR'}")
    print(f"Propriété D(E(M)) = M : {D1 == M and D2 == M}")


def demo_malleabilite(eg: ElGamal):
    M = 12345
    C1, C2 = eg.chiffrer(M)

    C2_forge = (2 * C2) % eg.p
    C_forge  = (C1, C2_forge)

    M_forge  = eg.dechiffrer(C_forge)
    attendu  = (2 * M) % eg.p

    print("=" * 65)
    print("PARTIE 3 — Malléabilité : forger E(2M) depuis E(M)")
    print("=" * 65)
    print(f"  Message original  M         = {M}")
    print(f"  Chiffré original  C         = (C1, C2)")
    print(f"  Chiffré forgé     C'        = (C1, 2·C2 mod p)")
    print(f"  Déchiffrement de C'         = {M_forge}")
    print(f"  Attendu : 2·M mod p         = {attendu}")
    print(f"  Forgerie réussie            : {M_forge == attendu}")
    print()
    print("  → Obtenu le chiffré de 2M sans connaître M ni x.")
    print("  → ElGamal est malleable : pas de protection d'intégrité.")

def demo_comparaison_rsa_elgamal():
    bits        = 2048
    taille_octet = bits // 8

    rsa_chiffre = taille_octet
    elg_chiffre = 2 * taille_octet

    print("=" * 65)
    print("PARTIE 4 — Comparaison RSA-2048 vs ElGamal-2048")
    print("=" * 65)
    print(f"\n{'Critère':<30} {'RSA-2048':>12} {'ElGamal-2048':>14}")
    print("-" * 58)
    print(f"{'Taille clé publique (oct)':<30} {taille_octet:>12} {taille_octet:>14}")
    print(f"{'Taille chiffré (oct)':<30} {rsa_chiffre:>12} {elg_chiffre:>14}")
    print(f"{'Nb entiers dans le chiffré':<30} {'1':>12} {'2 (C1,C2)':>14}")
    print(f"{'Non-déterministe':<30} {'Non':>12} {'Oui':>14}")
    print(f"{'Malleable (sans MAC)':<30} {'Non*':>12} {'Oui':>14}")
    print("-" * 58)

if __name__ == "__main__":
    eg = ElGamal(bits=512)

    demo_chiffrement(eg)
    print()
    demo_malleabilite(eg)
    print()
    demo_comparaison_rsa_elgamal()