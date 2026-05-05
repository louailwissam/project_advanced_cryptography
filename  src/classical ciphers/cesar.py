from crypto_base import AlgorithmeCryptographique
from collections import Counter

class Cesar(AlgorithmeCryptographique):
    # --- 1. TES FONCTIONS DE BASE ---
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

    # --- 2. EXIGENCES DU TP 1 (Exercice 1.1) ---
    def attaque_force_brute(self, texte_chiffre):
        """ Teste les 26 clés possibles et cherche des mots français """
        mots_courants =["LE", "LA", "LES", "DE", "UN", "UNE", "ET", "EST"]
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

        return meilleure_cle, meilleur_texte

    def calcul_indice_coincidence(self, texte):
        texte = ''.join(filter(str.isalpha, texte.upper()))
        N = len(texte)
        if N <= 1: return 0
        frequences = Counter(texte)
        ic = sum(f * (f - 1) for f in frequences.values()) / (N * (N - 1))
        return ic

    def attaque_frequences(self, texte_chiffre):
        texte_filtre = ''.join(filter(str.isalpha, texte_chiffre.upper()))
        frequences = Counter(texte_filtre)
        lettre_max = frequences.most_common(1)[0][0]
        # On suppose que la lettre la plus fréquente est le 'E' (ASCII 69)
        cle_deduite = (ord(lettre_max) - 69) % 26
        return cle_deduite