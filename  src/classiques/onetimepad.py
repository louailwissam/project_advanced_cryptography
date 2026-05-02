from crypto_base import AlgorithmeCryptographique
import os

class OneTimePad(AlgorithmeCryptographique):
    # --- 1. TES FONCTIONS DE BASE (Alphabétique Modulo 26) ---
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

    # --- 2. EXIGENCES DU TP 1 (Exercice 1.4 : Mode Binaire et Vulnérabilité) ---
    def chiffrer_xor_tp(self, texte_clair_bytes, cle_bytes):
        return bytes(a ^ b for a, b in zip(texte_clair_bytes, cle_bytes))

    def attaque_reutilisation_cle(self, c1, c2, mot_devine):
        """ Attaque Crib Dragging """
        m1_xor_m2 = bytes(a ^ b for a, b in zip(c1, c2))
        crib_bytes = mot_devine.encode('utf-8')
        resultats =[]
        for i in range(len(m1_xor_m2) - len(crib_bytes) + 1):
            extrait = m1_xor_m2[i:i+len(crib_bytes)]
            resultat_xor = bytes(a ^ b for a, b in zip(extrait, crib_bytes))
            # On vérifie si les caractères sont imprimables (lisibles)
            if all(32 <= b <= 126 or b.isalpha() for b in resultat_xor):
                resultats.append((i, resultat_xor.decode('utf-8', errors='ignore')))
        return resultats