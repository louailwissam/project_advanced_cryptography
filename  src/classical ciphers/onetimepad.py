import sys
import os

# Permet de trouver 'crypto_base.py'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_base import AlgorithmeCryptographique


class OneTimePad(AlgorithmeCryptographique):
    def chiffrer(self, texte_clair, cle):
        texte_clair = texte_clair.upper().replace(" ", "")
        cle = cle.upper().replace(" ", "")
        if len(texte_clair) > len(cle):
            raise ValueError("OTP: La clé doit être au moins aussi longue que le texte.")

        resultat = ""
        for i in range(len(texte_clair)):
            if texte_clair[i].isalpha() and cle[i].isalpha():
                shift = ord(cle[i]) - 65
                resultat += chr((ord(texte_clair[i]) - 65 + shift) % 26 + 65)
            else:
                resultat += texte_clair[i]
        return resultat

    def dechiffrer(self, texte_chiffre, cle):
        texte_chiffre = texte_chiffre.upper().replace(" ", "")
        cle = cle.upper().replace(" ", "")

        resultat = ""
        for i in range(len(texte_chiffre)):
            if texte_chiffre[i].isalpha() and cle[i].isalpha():
                shift = ord(cle[i]) - 65
                resultat += chr((ord(texte_chiffre[i]) - 65 - shift) % 26 + 65)
            else:
                resultat += texte_chiffre[i]
        return resultat

    def chiffrer_xor_tp(self, texte_clair_bytes, cle_bytes):
        return bytes(a ^ b for a, b in zip(texte_clair_bytes, cle_bytes))

    def attaque_reutilisation_cle(self, c1, c2, mot_devine):
        m1_xor_m2 = bytes(a ^ b for a, b in zip(c1, c2))
        crib_bytes = mot_devine.encode('utf-8')
        resultats = []
        for i in range(len(m1_xor_m2) - len(crib_bytes) + 1):
            extrait = m1_xor_m2[i:i + len(crib_bytes)]
            resultat_xor = bytes(a ^ b for a, b in zip(extrait, crib_bytes))
            if all(32 <= b <= 126 or b.isalpha() for b in resultat_xor):
                resultats.append((i, resultat_xor.decode('utf-8', errors='ignore')))
        return resultats


# ==========================================
# MENU DE TEST (S'exécute si on lance ce fichier)
# ==========================================
if __name__ == "__main__":
    print("=" * 50)
    print(" TEST TP 1 - ONE-TIME PAD (OTP)")
    print("=" * 50)
    algo = OneTimePad()

    msg = input("Texte à chiffrer : ")
    cle = input(f"Clé (lettres, au moins {len(msg)} caractères) : ")
    try:
        chiffre = algo.chiffrer(msg, cle)
        print(f"\n[+] Chiffré   : {chiffre}")
        print(f"[+] Déchiffré : {algo.dechiffrer(chiffre, cle)}")
    except ValueError as e:
        print(f"Erreur : {e}")

    print("\n--- Vulnérabilité (Crib Dragging) ---")
    c1 = algo.chiffrer_xor_tp(b"SECRET MESSAGE", b"SUPER CLEF 123")
    c2 = algo.chiffrer_xor_tp(b"ATTACK AT DAWN", b"SUPER CLEF 123")
    print("M1='SECRET MESSAGE', M2='ATTACK AT DAWN', chiffrés avec la même clé binaire.")
    print("Attaque : On cherche le mot 'MESSAGE'...")
    res = algo.attaque_reutilisation_cle(c1, c2, "MESSAGE")
    for pos, txt in res:
        print(f"Position {pos} : Partie de l'autre message révélée = '{txt}'")