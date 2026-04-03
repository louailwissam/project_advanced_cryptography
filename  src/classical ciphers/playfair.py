import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto_base import AlgorithmeCryptographique
class Playfair(AlgorithmeCryptographique):

    ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVXYZ"  # 25 lettres sans W

    def _construire_matrice(self, cle: str):
        cle = cle.upper().replace("W", "X")  # remplacer w par x
        seen = []  # construire un vecteur plat tout dabors

        for ch in cle:  # ajouter la cle sans doublons
            if ch.isalpha() and ch not in seen:
                seen.append(ch)

        for ch in self.ALPHABET:  # continuer a remplir la matrice
            if ch not in seen:
                seen.append(ch)

        # transformer le vecteur en matrice 5x5
        return [seen[i*5:(i+1)*5] for i in range(5)]
    # fonction qui retourne la ligne (row r) et la colonne(column c) for a specific letter

    def _trouver(self, matrice, lettre):
        for r in range(5):
            for c in range(5):
                if matrice[r][c] == lettre:
                    return r, c
    # preparer le texte(traiter les deux memes lettres consecutives ou bien un texte court)

    def _preparer(self, texte: str) -> str:
        texte = "".join(ch for ch in texte.upper().replace(
            "W", "X") if ch.isalpha())
        result = []
        i = 0
        while i < len(texte):
            a = texte[i]
            b = texte[i+1] if i+1 < len(texte) else "X"
            if a == b:
                result += [a, "X"]
                i += 1
            else:
                result += [a, b]
                i += 2
        return "".join(result)
     # traiter les paires de lettres(s'ils sont dans la meme ligne, colonne ou bien rectangle)

    def _traiter_paire(self, a, b, matrice, d):
        ra, ca = self._trouver(matrice, a)
        rb, cb = self._trouver(matrice, b)
        if ra == rb:  # même ligne
            return matrice[ra][(ca+d) % 5] + matrice[rb][(cb+d) % 5]
        if ca == cb:  # même colonne
            return matrice[(ra+d) % 5][ca] + matrice[(rb+d) % 5][cb]
        return matrice[ra][cb] + matrice[rb][ca]  # rectangle
  # chiffrer le texte

    def chiffrer(self, texte_clair: str, cle: str) -> str:
        m = self._construire_matrice(cle)
        texte = self._preparer(texte_clair)
        return "".join(self._traiter_paire(texte[i], texte[i+1], m, +1)
                       for i in range(0, len(texte), 2))
  # dechiffre le message

    def dechiffrer(self, texte_chiffre: str, cle: str) -> str:
        m = self._construire_matrice(cle)
        texte = "".join(ch for ch in texte_chiffre.upper() if ch.isalpha())
        return "".join(self._traiter_paire(texte[i], texte[i+1], m, -1)
                       for i in range(0, len(texte), 2))


# exemple du cours slide 19)
if __name__ == "__main__":
    pf = Playfair()
    cle = "TEST PLAYFAIR"

    chiffre = pf.chiffrer("MAGICSQUARES", cle)
    dechiffre = pf.dechiffrer(chiffre, cle)

    print(f"Clair    : MAGICSQUARES")
    print(f"Chiffré  : {chiffre}")
    print(f"Déchiffré: {dechiffre}")
