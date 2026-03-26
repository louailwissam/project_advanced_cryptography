import sys
import os

# 1. On force Python à inclure le dossier 'src' dans ses recherches
dossier_src = os.path.abspath(os.path.join(os.path.dirname(__file__), 'src'))
sys.path.insert(0, dossier_src)

# 2. Maintenant on peut importer sans utiliser le mot 'src' !
from classiques.cesar import Cesar
from classiques.onetimepad import OneTimePad
from modernes.aes import AESAlgo

def main():
    print("="*50)
    print(" PROJET DE CRYPTOGRAPHIE AVANCÉE")
# ... (le reste de ton code main.py reste exactement le même)


def main():
    print("=" * 50)
    print(" PROJET DE CRYPTOGRAPHIE AVANCÉE")
    print("=" * 50)

    while True:
        print("\nMenu des algorithmes :")
        print("1. Chiffre de César")
        print("2. Masque Jetable (OTP)")
        print("3. AES-128 ")
        print("4. Quitter")

        choix = input("\nChoisissez un algorithme (1-4) : ")

        if choix == '1':
            algo = Cesar()
            msg = input("Texte à chiffrer : ")
            cle = input("Clé (nombre entier) : ")
            chiffre = algo.chiffrer(msg, cle)
            print(f"-> Chiffré : {chiffre}")
            print(f"-> Déchiffré: {algo.dechiffrer(chiffre, cle)}")

        elif choix == '2':
            algo = OneTimePad()
            msg = input("Texte à chiffrer : ")
            print("RAPPEL: La clé doit avoir la même longueur que le texte.")
            cle = input("Clé (lettres) : ")
            try:
                chiffre = algo.chiffrer(msg, cle)
                print(f"-> Chiffré : {chiffre}")
                print(f"-> Déchiffré: {algo.dechiffrer(chiffre, cle)}")
            except ValueError as e:
                print(e)

        elif choix == '3':
            algo = AESAlgo()
            msg = input("Texte à chiffrer : ")
            cle = input("Clé (doit faire 16 caractères pour 128 bits) : ")
            if len(cle) != 16:
                print("Erreur: L'AES-128 requiert exactement 16 caractères.")
                continue

            chiffre = algo.chiffrer(msg, cle)
            print(f"-> Chiffré (Hexadécimal) : {chiffre}")
            print(f"-> Déchiffré: {algo.dechiffrer(chiffre, cle)}")

        elif choix == '4':
            print("Au revoir !")
            sys.exit(0)
        else:
            print("Choix invalide.")


if __name__ == "__main__":
    main()