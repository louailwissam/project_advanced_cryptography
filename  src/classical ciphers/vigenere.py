from itertools import combinations
from collections import defaultdict, Counter
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto_base import AlgorithmeCryptographique

class Vigenere(AlgorithmeCryptographique):

    ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    # fonction pour supprimer lespace et mettre le texte en majuscule

    def _normaliser(self, texte: str) -> str:
        return "".join(ch for ch in texte.upper() if ch.isalpha())
    # fonction qui sert a repeter la cle autant de fois que necessaire

    def _repeter_cle(self, cle: str, longueur: int) -> str:
        cle_norm = self._normaliser(cle)
        return (cle_norm * ((longueur // len(cle_norm)) + 1))[:longueur]
    # fonction pour chiffrer

    def chiffrer(self, texte_clair: str, cle: str) -> str:
        texte = self._normaliser(texte_clair)
        cle_etendue = self._repeter_cle(cle, len(texte))

        chiffre = []
        # zin function to give each pair from the key and clear text
        for p, k in zip(texte, cle_etendue):
            val = (self.ALPHABET.index(p) + self.ALPHABET.index(k)) % 26
            chiffre.append(self.ALPHABET[val])

        return "".join(chiffre)
    # fonction pour dechiffrer de meme facon que li chiffrement

    def dechiffrer(self, texte_chiffre: str, cle: str) -> str:
        texte = self._normaliser(texte_chiffre)
        cle_etendue = self._repeter_cle(cle, len(texte))

        clair = []
        for c, k in zip(texte, cle_etendue):
            val = (self.ALPHABET.index(c) - self.ALPHABET.index(k)) % 26
            clair.append(self.ALPHABET[val])

        return "".join(clair)

    def trouver_longueur_cle(self, texte_chiffre: str, min_longueur: int = 3) -> int:
        texte = self._normaliser(texte_chiffre)
        n = len(texte)

        # Trouver les sequences repetees
        sequences_repetee = defaultdict(list)

        # pour toutes les longueurs possibles
        for longueur_seq in range(min_longueur, min(10, n // 2)):
            print(f"Recherche séquences de longueur {longueur_seq}...")
            for i in range(n - longueur_seq + 1):
                seq1 = texte[i:i + longueur_seq]

                # Chercher cette sequence
                for j in range(i + 1, n - longueur_seq + 1):
                    seq2 = texte[j:j + longueur_seq]

                    if seq1 == seq2:  # sequence repetee
                        distance = j - i
                        sequences_repetee[seq1].append(
                            distance)  # ajoutee au dictionnaire
                        print(
                            f"trouve '{seq1}' a pos {i} et {j} (dist={distance})")

        if not sequences_repetee:
            print("aucune sequence repetee touve")
            return 4

        # Affichage
        print("\n sequences repetees trouve")
        print("pos1 | pos2 | distance | facteurs")

        toutes_distances = []
        for seq, distances in sequences_repetee.items():
            seq_len = len(seq)
            print(f"\nsequence '{seq}' (L={seq_len}) :")
            for i, dist in enumerate(distances[:5]):  # indexee la liste
                pos1 = "???"
                facteurs = self._facteurs(dist)  # trouver les facteurs
                print(f"  {pos1:4}  {pos1:4}  {dist:4}  {facteurs}")
                toutes_distances.append(dist)

        # analyse des facteurs (nbr d'ocuurence de chaque facteur dans chaque distance)
        print("\nanalyse des facteura :")
        facteurs_compteur = Counter()
        for dist in toutes_distances:
            for f in self._facteurs(dist):
                facteurs_compteur[f] += 1

        candidats = {k: v for k, v in facteurs_compteur.items()
                     if 2 <= k <= len(texte) // 4}

        print("Facteurs candidats (frequence) :")
        for k, v in sorted(candidats.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {k:2}: {v:2}")

        longueur_cle = max(candidats, key=candidats.get) if candidats else 4
        print(f"\n longueur de cle : {longueur_cle}")
        return longueur_cle
    # fonction pour trouver les facteurs d'un nombre

    def _facteurs(self, n: int) -> list:
        facteurs = []
        # range de 1 au racine carree
        for i in range(1, int(n**0.5) + 1):
            if n % i == 0:
                facteurs.append(i)
                if i != n // i:  # cas de racine carree
                    facteurs.append(n // i)
        return sorted(facteurs)
    # fonction de lanalyse frequntielle

    def analyse_frequences(self, texte: str) -> dict:
        texte = self._normaliser(texte)
        n = len(texte)
        freq = {}
        for ch in texte:
            freq[ch] = freq.get(ch, 0) + 1
        for ch in freq:
            freq[ch] = round(freq[ch] / n * 100, 2)
        return freq

    def trouver_cle(self, texte_chiffre: str, longueur_cle: int) -> str:
        texte = self._normaliser(texte_chiffre)
        cle = ""
        for position in range(longueur_cle):
            # slicing pour lanalyse frequentielle
            sous_texte = ""
            for i in range(position, len(texte), longueur_cle):
                sous_texte += texte[i]

            # Compter frequences
            freq = {}
            for ch in sous_texte:
                freq[ch] = freq.get(ch, 0) + 1

            # lettre la plus frequente
            lettre_freq = max(freq, key=freq.get)
            nb_occur = freq[lettre_freq]

            # deduction cle(lettre plus frequente en francais cest E)
            val_cle = (self.ALPHABET.index(lettre_freq) -
                       self.ALPHABET.index('E')) % 26
            lettre_cle = self.ALPHABET[val_cle]
            # affichage
            print(
                f"Position {position+1}: '{lettre_freq}' ({nb_occur}/{len(sous_texte)} = {nb_occur/len(sous_texte)*100:.1f}%) → '{lettre_cle}'")
            cle += lettre_cle

        print(f"\n cle : {cle}")
        return cle

    def indice_coincidence(self, texte: str) -> float:
        texte = self._normaliser(texte)
        n = len(texte)
        freq = {}
        for ch in texte:
            freq[ch] = freq.get(ch, 0) + 1

        numerateur = 0
        for v in freq.values():
            numerateur += v * (v - 1)
        return numerateur / (n * (n - 1))


if __name__ == "__main__":
    vig = Vigenere()

    # chiffrement / dechiffrement simple
    clair = "USTHIBUNIVERSITY"
    cle = "KEYS"
    chiffre = vig.chiffrer(clair, cle)
    retour = vig.dechiffrer(chiffre, cle)
    print(f"Clair    : {clair}")
    print(f"Clé      : {cle}")
    print(f"Chiffré  : {chiffre}")
    print(f"Déchiffré: {retour}")
    print()

    # Test Kasiski
    chiffre2 = ("CLCJSGEEXJGGOETFEUUUPEIRMOOBTGGRCOAKTLCHRCODGGOTDEFVC"
                "JJFHSEFFVKHEPFRGFSVRUGMAOFMGMEVURGTETBCJJFHSEGEEFJFHFRG"
                "OTGTMCOIGSEUMEEIIHGRGEEXJGGOETFEZJGGDOONERSEURUGMAVPT"
                "CMIVFDGTSATTGNEUEEEIIHGRGNEPUQWFLGTDGVXEPRTFSRPNFBNVTC"
                "QONCJSUFNVVNGDLGGSGDRGUEEPMOVNG")

    # trouver la longueur de la cle
    longueur = vig.trouver_longueur_cle(chiffre2)

    # trouver la cle par analyse frequentielle
    cle_trouvee = vig.trouver_cle(chiffre2, longueur)

    # dechiffrer
    clair2 = vig.dechiffrer(chiffre2, cle_trouvee)
    print(f"\ntexte clair apres dechiffrement kasiski:\n{clair2}")

    print(f"\nIC (chiffré)  : {vig.indice_coincidence(chiffre2):.4f}")
    print(f"IC (clair)    : {vig.indice_coincidence(clair2):.4f}")
