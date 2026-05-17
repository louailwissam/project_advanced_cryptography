import sys
import os
import secrets
import string
from collections import Counter

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from crypto_base import AlgorithmeCryptographique

FREQ_ANGLAIS = {
    'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0,
    'N': 6.7, 'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3,
    'L': 4.0, 'C': 2.8, 'U': 2.8, 'M': 2.4, 'W': 2.4,
    'F': 2.2, 'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.5,
    'V': 1.0, 'K': 0.8, 'J': 0.15,'X': 0.15,'Q': 0.10,
    'Z': 0.07,
}


class OneTimePad(AlgorithmeCryptographique):
    @staticmethod
    def generer_cle_alpha(longueur: int) -> str:
        #Génère une clé aléatoire cryptographiquement sûre (lettres majuscules)
        alphabet = string.ascii_uppercase
        return ''.join(secrets.choice(alphabet) for _ in range(longueur))

    @staticmethod
    def generer_cle_bytes(longueur: int) -> bytes:
        #Génère une clé aléatoire cryptographiquement sûre (octets bruts)
        return secrets.token_bytes(longueur)

    def chiffrer(self, texte_clair: str, cle: str) -> str:
        texte_clair = texte_clair.upper().replace(" ", "")
        cle         = cle.upper().replace(" ", "")
        if len(texte_clair) > len(cle):
            raise ValueError("OTP : la clé doit être au moins aussi longue que le texte.")
        resultat = ""
        for i in range(len(texte_clair)):
            if texte_clair[i].isalpha() and cle[i].isalpha():
                shift      = ord(cle[i]) - 65
                resultat  += chr((ord(texte_clair[i]) - 65 + shift) % 26 + 65)
            else:
                resultat  += texte_clair[i]
        return resultat

    def dechiffrer(self, texte_chiffre: str, cle: str) -> str:
        texte_chiffre = texte_chiffre.upper().replace(" ", "")
        cle           = cle.upper().replace(" ", "")
        resultat = ""
        for i in range(len(texte_chiffre)):
            if texte_chiffre[i].isalpha() and cle[i].isalpha():
                shift     = ord(cle[i]) - 65
                resultat += chr((ord(texte_chiffre[i]) - 65 - shift) % 26 + 65)
            else:
                resultat += texte_chiffre[i]
        return resultat

    def chiffrer_xor(self, texte_clair_bytes: bytes, cle_bytes: bytes) -> bytes:
        if len(texte_clair_bytes) > len(cle_bytes):
            raise ValueError("OTP-XOR : la clé doit être au moins aussi longue que le texte.")
        return bytes(a ^ b for a, b in zip(texte_clair_bytes, cle_bytes))

    # alias pour compatibilité avec votre ancien code
    chiffrer_xor_tp = chiffrer_xor

    def dechiffrer_xor(self, texte_chiffre_bytes: bytes, cle_bytes: bytes) -> bytes:
        """XOR est sa propre inverse : déchiffrer == chiffrer."""
        return self.chiffrer_xor(texte_chiffre_bytes, cle_bytes)

    def xor_deux_chiffres(self, c1: bytes, c2: bytes) -> bytes:
        """Calcule C1 XOR C2 = M1 XOR M2 (la clé s'annule)."""
        return bytes(a ^ b for a, b in zip(c1, c2))

    def analyser_xor_messages(self, m1_xor_m2: bytes) -> None:
  
        print("\n  Distribution des octets de M1⊕M2 :")
        printable = [b for b in m1_xor_m2 if 0x20 <= b <= 0x7E]
        non_print = len(m1_xor_m2) - len(printable)
        print(f"  Octets imprimables : {len(printable)}/{len(m1_xor_m2)}")
        print(f"  Octets non-imprimables : {non_print}")
        print(f"  Valeur moyenne  : {sum(m1_xor_m2)/len(m1_xor_m2):.1f} "
              f"(texte aléatoire ≈ 127.5)")
        freq = Counter(m1_xor_m2)
        top5 = freq.most_common(5)
        print(f"  Top 5 octets    : {[(hex(b), n) for b, n in top5]}")

    def attaque_reutilisation_cle(
        self, c1: bytes, c2: bytes, mot_devine: str
    ) -> list[tuple[int, str]]:
        m1_xor_m2  = self.xor_deux_chiffres(c1, c2)
        crib_bytes  = mot_devine.encode('ascii')
        resultats   = []

        for i in range(len(m1_xor_m2) - len(crib_bytes) + 1):
            extrait      = m1_xor_m2[i : i + len(crib_bytes)]
            fragment_m2  = bytes(a ^ b for a, b in zip(extrait, crib_bytes))

            if all(32 <= b <= 126 and chr(b).isalpha() or chr(b) == ' '
                   for b in fragment_m2):
                texte = fragment_m2.decode('ascii', errors='replace')
                resultats.append((i, texte))

        return resultats

    @staticmethod
    def score_langue(texte: str) -> float:
        
        texte  = texte.upper()
        total  = sum(1 for c in texte if c.isalpha())
        if total == 0:
            return 0.0
        freq   = Counter(c for c in texte if c.isalpha())
        return sum(FREQ_ANGLAIS.get(c, 0) * n for c, n in freq.items()) / total


if __name__ == "__main__":
    algo = OneTimePad()
    sep  = "─" * 52
    print("=" * 52)
    print("  TEST TP – ONE-TIME PAD (OTP / Vernam)")
    print("=" * 52)

    msg = input("Texte à chiffrer : ").strip()
    cle_generee = OneTimePad.generer_cle_alpha(len(msg.replace(" ", "")))
    print(f"  Clé auto-générée (aléatoire) : {cle_generee}")
    choix = input("  Utiliser cette clé ? [o/n] : ").strip().lower()
    if choix != 'o':
        while True:
            cle = input(f"  Votre clé (≥ {len(msg.replace(' ',''))} lettres) : ").strip()
            if len(cle.replace(" ", "")) >= len(msg.replace(" ", "")):
                break
            print("  ⚠ Clé trop courte, réessayez.")
    else:
        cle = cle_generee

    try:
        chiffre    = algo.chiffrer(msg, cle)
        dechiffre  = algo.dechiffrer(chiffre, cle)
        print(f"\n  Texte clair  : {msg.upper().replace(' ','')}")
        print(f"   Clé utilisée : {cle.upper().replace(' ','')}")
        print(f"  Chiffré      : {chiffre}")
        print(f"  Déchiffré    : {dechiffre}")
        assert dechiffre == msg.upper().replace(" ", ""), "ERREUR : restitution incorrecte !"
        print("  [✓] Restitution exacte vérifiée.")
    except ValueError as e:
        print(f"  Erreur : {e}")
    print(f"\n{sep}")
    print("  VULNÉRABILITÉ – Réutilisation de clé (XOR)")
    print(sep)
    M1 = b"ATTACK AT DAWN"
    M2 = b"SECRET MESSAGE"
    K  = OneTimePad.generer_cle_bytes(len(M1))   # clé aléatoire sûre

    C1 = algo.chiffrer_xor(M1, K)
    C2 = algo.chiffrer_xor(M2, K)

    print(f"  M1 = {M1}")
    print(f"  M2 = {M2}")
    print(f"  K  = {K.hex()}")
    print(f"  C1 = {C1.hex()}")
    print(f"  C2 = {C2.hex()}")

    # Vérification déchiffrement
    assert algo.dechiffrer_xor(C1, K) == M1, "ERREUR déchiffrement C1"
    assert algo.dechiffrer_xor(C2, K) == M2, "ERREUR déchiffrement C2"
    print("  Chiffrement/déchiffrement XOR vérifiés.")

    M1_xor_M2 = algo.xor_deux_chiffres(C1, C2)
    print(f"\n  C1 xor C2 = M1 xor M2 = {M1_xor_M2.hex()}")
    print("  → La clé K est totalement éliminée !")

    print(f"\n{sep}")
    print("  ANALYSE STATISTIQUE DE M1 xor M2")
    print(sep)
    algo.analyser_xor_messages(M1_xor_M2)
    print("\n  Interprétation :")
    print("  Si les messages sont du texte ASCII, ~50 % des octets")
    print("  de M1 xor M2 tombent dans 0x00–0x3F (texte minusculexormajuscule)")
    print("  ce qui révèle la NATURE du contenu (texte, binaire, etc.).")
    print(f"\n{sep}")
    print("  ATTAQUE CRIB DRAGGING")
    print(sep)
    crib = "ATTACK"
    print(f"  Crib (mot supposé dans M1) : '{crib}'")
    resultats = algo.attaque_reutilisation_cle(C1, C2, crib)
    if resultats:
        for pos, fragment in resultats:
            score = algo.score_langue(fragment)
            print(f"  Position {pos:2d} | Fragment de M2 révélé : '{fragment}' "
                  f"| Score langue : {score:.1f}")
    else:
        print("  Aucune position ne donne un fragment entièrement alphabétique.")
        # Affichage brut pour analyse manuelle
        print("  Aperçu brut (M1xorM2 xor crib) par position :")
        m1_xor_m2_bytes = algo.xor_deux_chiffres(C1, C2)
        crib_b = crib.encode('ascii')
        for i in range(len(m1_xor_m2_bytes) - len(crib_b) + 1):
            extrait = m1_xor_m2_bytes[i:i+len(crib_b)]
            fragment = bytes(a ^ b for a, b in zip(extrait, crib_b))
  