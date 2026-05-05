from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1, generate_private_key, ECDH
)
import sys
import os
import hashlib
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from crypto_base import AlgorithmeCryptographique

class CourbePedagogique:
  # initialisation des parametres de la courbe
    def __init__(self, a: int = 0, b: int = 7, p: int = 97):
        self.a = a
        self.b = b
        self.p = p
        self._verifier_discriminant()
  # assurer que la courbe est valide

    def _verifier_discriminant(self):
        delta = (-16 * (4 * self.a**3 + 27 * self.b**2)) % self.p
        assert delta != 0, "Discriminant nul = courbe singuliere "
  # verifier qu'un point satisfait l'equation

    def sur_courbe(self, P) -> bool:
        if P is None:
            return True
        x, y = P
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0

    # calculer linverse de n, (theoreme de fermat)
    def _inv(self, n: int) -> int:
        return pow(n % self.p, self.p - 2, self.p)

    def additionner(self, P, Q):
        # Élément neutre
        if P is None:
            return Q
        if Q is None:
            return P

        x1, y1 = P
        x2, y2 = Q

        # P = -Q
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None

        if P == Q:
            # on utilise la tangente
            if y1 == 0:
                return None
            lam = (3 * x1 * x1 + self.a) * self._inv(2 * y1) % self.p
        else:
            # corde
            lam = (y2 - y1) * self._inv(x2 - x1) % self.p

        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)

    # multiplication scalaire
    def multiplier(self, k: int, P):
        # algo double and add
        result = None
        courant = P
        while k > 0:
            if k & 1:
                result = self.additionner(result, courant)
            courant = self.additionner(courant, courant)
            k >>= 1
        return result

    # kp=ele neutre
    def ordre_point(self, P, max_iter: int = 10000) -> int:
        Q = P
        for k in range(1, max_iter):
            if Q is None:
                return k
            Q = self.additionner(Q, P)
        return -1   # non trouve

    # enumere par force brute tous les points (x, y) de la courbe
    def points(self) -> list:
        """Enumère tous les points affines de la courbe (+ point à l'infini)."""
        pts = [None]
        for x in range(self.p):
            rhs = (x**3 + self.a * x + self.b) % self.p
            for y in range(self.p):
                if y * y % self.p == rhs:
                    pts.append((x, y))
        return pts

    # Verifie les proprietes de groupe
    def verifier_proprietes(self, P, Q):
        print(f"COURBE  y² = x³ + {self.a}x + {self.b}  mod {self.p}")
        assert self.sur_courbe(P), f"P={P} n'est pas sur la courbe "
        assert self.sur_courbe(Q), f"Q={Q} n'est pas sur la courbe "
        print(f"\n  P = {P}   sur courbe : {self.sur_courbe(P)}")
        print(f"  Q = {Q}   sur courbe : {self.sur_courbe(Q)}")

        # fermeture(p+q sur lacourbe)
        PpQ = self.additionner(P, Q)
        print(
            f"\n  1. Fermeture   : P + Q = {PpQ}   sur courbe : {self.sur_courbe(PpQ)}")

        # commutativite
        QpP = self.additionner(Q, P)
        print(f"  2. Commutativité : P + Q = Q + P : {PpQ == QpP}")

        # associativite
        R = self.additionner(P, Q)
        lhs = self.additionner(R, Q)
        rhs = self.additionner(P, self.additionner(Q, Q))
        print(f"  3. Associativité : (P+Q)+Q = P+(Q+Q) : {lhs == rhs}")

        # element neutre
        PpO = self.additionner(P, None)
        print(f"  4. Élément neutre : P + O = {PpO} = P : {PpO == P}")

        # inverse
        neg_P = (P[0], (-P[1]) % self.p)
        inv = self.additionner(P, neg_P)
        print(f"  5. Inverse : P + (-P) = {inv} = O : {inv is None}")

        # ordre du point
        ord_P = self.ordre_point(P)
        print(f"\n  Ordre de P : {ord_P}")
        print(f"  Nombre total de points (y compris O) : {len(self.points())}")

        # ECDLP illustre
        k = 7
        kP = self.multiplier(k, P)
        print(f"\n  ECDLP : k=7, P={P} → k·P = {kP}")
        print(f"  (Retrouver k a partir de P et k·P est difficile sur de grandes courbes)")


# partie 2

class ECDH_P256:
    # Genere une paire (cle privee, cle publique) sur la courbe NIST P-256
    def generer_paire(self):
        priv = generate_private_key(SECP256R1(), default_backend())
        return priv, priv.public_key()
    # calcule le secret partage ECDH.

    def calculer_secret(self, ma_cle_privee, cle_publique_autre: bytes) -> bytes:
        return ma_cle_privee.exchange(ECDH(), cle_publique_autre)
# Derive une clee AES-256 (32 octets) via SHA-256

    def deriver_cle_aes(self, secret_brut: bytes) -> bytes:
        return hashlib.sha256(secret_brut).digest()

    def simuler_echange(self):
        print("   ECDH P-256 — echange de cles + Derivation AES-256")

        # Alice
        a_priv, a_pub = self.generer_paire()
        # Bob
        b_priv, b_pub = self.generer_paire()

        a_pub_bytes = a_pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        b_pub_bytes = b_pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        print(f"\n[Alice] Cle publique P-256 ({len(a_pub_bytes)} octets PEM)")
        print(f"[Bob]   Clé publique P-256 ({len(b_pub_bytes)} octets PEM)")

        # Calcul du secret partage
        secret_alice = self.calculer_secret(a_priv, b_pub)
        secret_bob = self.calculer_secret(b_priv, a_pub)

        assert secret_alice == secret_bob, "Secrets differents"
        print(
            f"\nSecret ECDH partage ({len(secret_alice)} octets) : {secret_alice.hex()}")

        # derivation AES-256
        cle_aes_alice = self.deriver_cle_aes(secret_alice)
        cle_aes_bob = self.deriver_cle_aes(secret_bob)

        assert cle_aes_alice == cle_aes_bob
        print(f"Cle AES-256 derivee (SHA-256) : {cle_aes_alice.hex()}")
        print(f"\n Alice et Bob ont la même cle AES-256 sans jamais se la transmettre.")

        return cle_aes_alice, a_priv, a_pub, b_priv, b_pub


# partie 3= chiffrement hybride

class ECIES(AlgorithmeCryptographique):

    def __init__(self):
        self.ecdh = ECDH_P256()

    def chiffrer(self, message, cle_publique_bob) -> dict:
        if isinstance(message, str):
            message = message.encode('utf-8')

        # paire(cle privee, cle publique)  d'Alice
        e_priv, e_pub = self.ecdh.generer_paire()

        # secret partage
        secret = e_priv.exchange(ECDH(), cle_publique_bob)

        # deriver la cle AES-256
        cle_aes = hashlib.sha256(secret).digest()

        # chiffrement AES-256-GCM
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(cle_aes), modes.GCM(iv),
                        backend=default_backend())
        enc = cipher.encryptor()
        chiffre = enc.update(message) + enc.finalize()
        tag = enc.tag

        e_pub_bytes = e_pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return {
            'e_pub': e_pub_bytes,    # cle publique d'Alice
            'iv': iv,             # vecteur d'initialisation AES
            'tag': tag,            # tag d'authentification GCM
            'chiffre': chiffre         # donnees chiffrres
        }

    def dechiffrer(self, paquet: dict, cle_privee_bob) -> str:
        """
        Dechiffre le paquet ECIES avec la cle privre de Bob.
        Retourne le message en clair (str).
        """
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        e_pub = load_pem_public_key(paquet['e_pub'], backend=default_backend())

        # Recalculer le secret partage
        secret = cle_privee_bob.exchange(ECDH(), e_pub)
        cle_aes = hashlib.sha256(secret).digest()

        # dechiffrement AES-256-GCM
        cipher = Cipher(
            algorithms.AES(cle_aes),
            modes.GCM(paquet['iv'], paquet['tag']),
            backend=default_backend()
        )
        dec = cipher.decryptor()
        clair = dec.update(paquet['chiffre']) + dec.finalize()
        return clair.decode('utf-8')

    def demo_complet(self):
        print("   ECIES SIMPLIFIE — Chiffrement hybride ECDH + AES-256-GCM")

        # Bob genere sa paire statique
        bob_priv, bob_pub = self.ecdh.generer_paire()
        print("\nBob  genere Paire de clés P-256 .")

        message = "Bonjour Bob ,Ceci est un message ultra-secret chiffre via ECIES."
        print(f"Alice Message clair : \"{message}\"")

        # Alice chiffre pour Bob
        paquet = self.chiffrer(message, bob_pub)
        print(f"\n[Alice] Paquet ECIES envoye a Bob :")
        print(
            f" e_pub  : {len(paquet['e_pub'])} octets (cle publique)")
        print(f" iv     : {paquet['iv'].hex()}")
        print(f"tag    : {paquet['tag'].hex()}")
        print(f"chiffre: {paquet['chiffre'].hex()}")

        # Bob dechiffre
        clair = self.dechiffrer(paquet, bob_priv)
        print(f"\n[Bob] Message dechiffre : \"{clair}\"")
        print(f"[OK] Integrite verifiee (GCM tag) : {clair == message}")


if __name__ == "__main__":

    print("\npartie  1 : Courbe y² = x³ + 7  mod 97\n")
    courbe = CourbePedagogique(a=0, b=7, p=97)

    # Trouver un point valide sur la courbe
    pts = courbe.points()
    P = pts[1]   # premier point affine
    Q = pts[3]   # autre point affine
    courbe.verifier_proprietes(P, Q)

    print(f"\n  Quelques points de la courbe (5 premiers) :")
    for pt in pts[1:6]:
        print(f"    {pt} sur courbe : {courbe.sur_courbe(pt)}")

    print("\npartie 2 : ECDH sur P-256 ")
    ecdh = ECDH_P256()
    ecdh.simuler_echange()

    print("\npartie3   : ECIES Chiffrement hybride complet")
    ecies = ECIES()
    ecies.demo_complet()
