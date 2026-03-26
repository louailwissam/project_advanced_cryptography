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
                # Addition modulo 26 (A=0, B=1...)
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
                # Soustraction modulo 26
                shift = ord(cle[i]) - 65
                resultat += chr((ord(texte_chiffre[i]) - 65 - shift) % 26 + 65)
            else:
                resultat += texte_chiffre[i]
        return resultat