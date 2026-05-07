import sys
import os

# Permet de trouver 'crypto_base.py' qui est dans le dossier parent (src)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_base import AlgorithmeCryptographique
from collections import Counter


class Cesar(AlgorithmeCryptographique):
    def chiffrer(self, texte_clair, cle):
        cle = int(cle)
        resultat = ""
        for char in texte_clair:
            if char.isalpha():
                ascii_base = 65 if char.isupper() else 97
                nouveau_char = chr((ord(char) - ascii_base + cle) % 26 + ascii_base)
                resultat += nouveau_char
            else:
                resultat += char
        return resultat

    def dechiffrer(self, texte_chiffre, cle):
        return self.chiffrer(texte_chiffre, -int(cle))

    def attaque_force_brute(self, texte_chiffre):
        mots_courants = ["LE", "LA", "LES", "DE", "UN", "UNE", "ET", "EST"]
        meilleure_cle = 0
        max_score = 0
        meilleur_texte = ""
        for k in range(26):
            texte_decode = self.dechiffrer(texte_chiffre, k)
            score = sum(1 for mot in mots_courants if mot in texte_decode.upper())
            if score > max_score:
                max_score = score
                meilleure_cle = k
                meilleur_texte = texte_decode
        print(f"Clé déduite (Force Brute) : {meilleure_cle}")
        print(f"Texte trouvé : {meilleur_texte}")
        return meilleure_cle, meilleur_texte

    def calcul_indice_coincidence(self, texte):
        texte = ''.join(filter(str.isalpha, texte.upper()))
        N = len(texte)
        if N <= 1: return 0
        frequences = Counter(texte)
        ic = sum(f * (f - 1) for f in frequences.values()) / (N * (N - 1))
        return ic


# ==========================================
# MENU DE TEST (S'exécute si on lance ce fichier)
# ==========================================
if __name__ == "__main__":
    print("=" * 50)
    print(" TEST TP 1 - CHIFFRE DE CÉSAR")
    print("=" * 50)
    algo = Cesar()

    msg = input("Texte à chiffrer : ")
    cle = input("Clé (nombre entier) : ")
    chiffre = algo.chiffrer(msg, cle)
    print(f"\n[+] Chiffré   : {chiffre}")
    print(f"[+] Déchiffré : {algo.dechiffrer(chiffre, cle)}")

    print("\n--- Attaque par Force Brute ---")
    algo.attaque_force_brute(chiffre)

    print("\n--- Analyse de Fréquences ---")
    ic = algo.calcul_indice_coincidence(chiffre)
    print(f"Indice de Coïncidence : {ic:.4f} (Si proche de 0.074 = Français)")