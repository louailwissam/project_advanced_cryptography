import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import random
from sympy import nextprime
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from crypto_base import AlgorithmeCryptographique

class DiffieHellman(AlgorithmeCryptographique):
 

    def __init__(self, bits: int = 512):
        self.bits = bits
        self.p = None
        self.g = 35   #simulation
        self._generer_parametres()

    def _generer_parametres(self):
        debut = 2 ** (self.bits - 1)
        self.p = nextprime(random.randint(debut, 2 * debut))
        print(f"[DH] Paramètres publics :")
        print(f"     p ({self.p.bit_length()} bits) = {str(self.p)[:60]}...")
        print(f"     g = {self.g}\n")

    def generer_cle_privee(self) -> int:
        return random.randint(2, self.p - 2)

    def cle_publique(self, x: int) -> int:
        return pow(self.g, x, self.p)

    def secret_partage(self, cle_pub_autre: int, x: int) -> int:
        return pow(cle_pub_autre, x, self.p)

    def chiffrer(self, texte_clair, cle):
        raise NotImplementedError("DH est un protocole d'échange, pas un chiffrement direct.")

    def dechiffrer(self, texte_chiffre, cle):
        raise NotImplementedError("DH est un protocole d'échange, pas un déchiffrement direct.")

    
    def simuler_echange(self) -> int:
        print("ÉCHANGE DIFFIE-HELLMAN — Simulation complète")

        a = self.generer_cle_privee()
        A = self.cle_publique(a)
        b = self.generer_cle_privee()
        B = self.cle_publique(b)

        print(f"[Alice] clé privée  a  = {a}")
        print(f"[Alice] clé publique A = g^a mod p = {str(A)[:50]}...\n")
        print(f"[Bob]   clé privée  b  = {b}")
        print(f"[Bob]   clé publique B = g^b mod p = {str(B)[:50]}...\n")
        print("[Canal public] Alice → Bob : A")
        print("[Canal public] Bob → Alice : B\n")

        K_alice = self.secret_partage(B, a)
        K_bob   = self.secret_partage(A, b)

        assert K_alice == K_bob, "Erreur : secrets différents !"
        print(f"[Alice] K = B^a mod p = {str(K_alice)[:50]}...")
        print(f"[Bob]   K = A^b mod p = {str(K_bob)[:50]}...")
        print(f"\n[OK] Secret partagé K identique des deux côtés.")
        print("=" * 65)
        return K_alice



#Attaque Man-in-the-Middle

class AttaqueMITM:

    def __init__(self, dh: DiffieHellman):
        self.dh = dh

    def simuler(self):
        p, g = self.dh.p, self.dh.g
        a  = self.dh.generer_cle_privee();  A  = pow(g, a,  p)
        b  = self.dh.generer_cle_privee();  B  = pow(g, b,  p)
        m1 = self.dh.generer_cle_privee();  M1 = pow(g, m1, p)
        m2 = self.dh.generer_cle_privee();  M2 = pow(g, m2, p)

   
        K_am = pow(M2, a,  p)   #alice croit parler à Bob
        K_mb = pow(B,  m1, p)   #bob croit parler à Alice

        print(f"K_Alice avec Mallory = {str(K_am)[:50]}...")
        print(f"K_Mallory avec Bob   = {str(K_mb)[:50]}...")
        print("\nAlice et Bob ont des secrets DIFFÉRENTS :Mallory est au milieu.")
        print("=" * 65)
        return K_am, K_mb



class DiffieHellmanECDSA:
    """
    Chaque partie signe sa clé publique DH avec ECDSA (P-256).
    Le destinataire vérifie la signature avant d'accepter la clé.
    ;'attaquant ne peut plus substituer ses valeurs sans invalider la signature.
    """

    def __init__(self, dh: DiffieHellman):
        self.dh = dh
  #generation des cles privee et publique de la signature
    def _paire_ecdsa(self):
        priv = generate_private_key(SECP256R1(), default_backend())
        return priv, priv.public_key()
   #signer les donnees
    def _signer(self, priv, valeur: int) -> bytes:
        data = valeur.to_bytes((valeur.bit_length() + 7) // 8, 'big')
        return priv.sign(data, ec.ECDSA(hashes.SHA256()))
   #verification de la corespondance des cles
    def _verifier(self, pub, valeur: int, sig: bytes) -> bool:
        data = valeur.to_bytes((valeur.bit_length() + 7) // 8, 'big')
        try:
            pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def simuler_echange_authentifie(self):
        print("   DH + ECDSA — Échange authentifié (contre-mesure MITM)")

        a = self.dh.generer_cle_privee();  A = pow(self.dh.g, a, self.dh.p)
        b = self.dh.generer_cle_privee();  B = pow(self.dh.g, b, self.dh.p)

        ecdsa_a_priv, ecdsa_a_pub = self._paire_ecdsa()
        ecdsa_b_priv, ecdsa_b_pub = self._paire_ecdsa()

        sig_A = self._signer(ecdsa_a_priv, A)
        sig_B = self._signer(ecdsa_b_priv, B)

        ok_bob   = self._verifier(ecdsa_a_pub, A, sig_A)
        ok_alice = self._verifier(ecdsa_b_pub, B, sig_B)

        print(f"A signe A avec ECDSA P-256 → {len(sig_A)} octets")
        print(f"B Vérifie signature de A : {'ok' if ok_bob   else 'echec'}")
        print(f"B Signe B avec ECDSA P-256 → {len(sig_B)} octets")
        print(f"A Vérifie signature de B : {'ok' if ok_alice else 'echec'}")

        if ok_alice and ok_bob:
            K = pow(B, a, self.dh.p)
            print(f"\nechange authentifié K = {str(K)[:50]}...")
            print("Man attaque ne peut plus substituer ses valeurs.")
        else:
            print("\nSignature invalide attaque MITM possible ")
        print("=" * 65)


if __name__ == "__main__":
    dh = DiffieHellman(bits=512)

    print("\nPARTIE 1 : Échange DH normal ───\n")
    dh.simuler_echange()

    print("\nPARTIE 2 : Attaque MITM ───")
    AttaqueMITM(dh).simuler()

    print("\nPARTIE 3 : Contre-mesure ECDSA ───")
    DiffieHellmanECDSA(dh).simuler_echange_authentifie()