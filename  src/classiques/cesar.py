from crypto_base import AlgorithmeCryptographique

class Cesar(AlgorithmeCryptographique):
    def chiffrer(self, texte_clair, cle):
        cle = int(cle)
        resultat = ""
        for char in texte_clair:
            if char.isalpha():
                ascii_base = 65 if char.isupper() else 97
                # Décalage circulaire modulo 26
                nouveau_char = chr((ord(char) - ascii_base + cle) % 26 + ascii_base)
                resultat += nouveau_char
            else:
                resultat += char
        return resultat

    def dechiffrer(self, texte_chiffre, cle):
        return self.chiffrer(texte_chiffre, -int(cle))