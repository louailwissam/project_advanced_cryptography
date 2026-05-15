

import sys
import os
import math



#  Utilitaires arithmétiques modulaires


TAILLE_ALPHABET = 26


def pgcd(x, y):
    while y:
        x, y = y, x % y
    return x


def inverse_multiplicatif(a, m=TAILLE_ALPHABET):
    """Algorithme d'Euclide étendu pour l'inverse mod m."""
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    raise ValueError(f"Pas d'inverse multiplicatif pour a={a} mod {m}")



#  Opérations matricielles mod 26


def determinant_2x2(mat):
    return (mat[0][0] * mat[1][1] - mat[0][1] * mat[1][0]) % TAILLE_ALPHABET


def inverse_mat_2x2(mat):
    """Inverse d'une matrice 2×2 mod 26 : det⁻¹ × adj(K)."""
    a, b = mat[0]
    c, d = mat[1]
    det = (a * d - b * c) % TAILLE_ALPHABET
    if det == 0 or pgcd(det, TAILLE_ALPHABET) != 1:
        raise ValueError(f"Matrice 2×2 non inversible (det={det} non premier avec 26).")
    det_inv = inverse_multiplicatif(det)
    # Adjointe
    return [
        [(det_inv *  d) % TAILLE_ALPHABET, (det_inv * -b) % TAILLE_ALPHABET],
        [(det_inv * -c) % TAILLE_ALPHABET, (det_inv *  a) % TAILLE_ALPHABET],
    ]


def determinant_3x3(mat):
    """Déterminant d'une matrice 3×3 mod 26 (développement selon la 1ʳᵉ ligne)."""
    a = mat
    det = (
        a[0][0] * (a[1][1]*a[2][2] - a[1][2]*a[2][1])
      - a[0][1] * (a[1][0]*a[2][2] - a[1][2]*a[2][0])
      + a[0][2] * (a[1][0]*a[2][1] - a[1][1]*a[2][0])
    ) % TAILLE_ALPHABET
    return det


def cofacteur_3x3(mat, i, j):
    """Cofacteur C_ij de mat (matrice 3×3)."""
    sous = [
        [mat[r][c] for c in range(3) if c != j]
        for r in range(3) if r != i
    ]
    mineur = (sous[0][0] * sous[1][1] - sous[0][1] * sous[1][0]) % TAILLE_ALPHABET
    signe = (-1) ** (i + j)
    return (signe * mineur) % TAILLE_ALPHABET


def inverse_mat_3x3(mat):
    """Inverse d'une matrice 3×3 mod 26 : det⁻¹ × adj(K)."""
    det = determinant_3x3(mat)
    if det == 0 or pgcd(det % TAILLE_ALPHABET, TAILLE_ALPHABET) != 1:
        raise ValueError(f"Matrice 3×3 non inversible (det={det % TAILLE_ALPHABET} non premier avec 26).")
    det_inv = inverse_multiplicatif(det % TAILLE_ALPHABET)
    # Matrice des cofacteurs transposée (adjointe)
    adj = [[cofacteur_3x3(mat, j, i) for j in range(3)] for i in range(3)]
    return [[(det_inv * adj[i][j]) % TAILLE_ALPHABET for j in range(3)] for i in range(3)]


def multiplier_mat_vecteur(mat, vec):
    """Produit matrice × vecteur mod 26."""
    n = len(vec)
    return [sum(mat[i][j] * vec[j] for j in range(n)) % TAILLE_ALPHABET for i in range(n)]


def multiplier_mat_mat(A, B, n):
    """Produit de deux matrices n×n mod 26."""
    return [
        [sum(A[i][k] * B[k][j] for k in range(n)) % TAILLE_ALPHABET for j in range(n)]
        for i in range(n)
    ]



#  Validation des clés


def valider_cle_2x2(cle):
   
    if not isinstance(cle, list) or len(cle) != 4:
        raise ValueError("Clé 2×2 : liste de 4 entiers [a, b, c, d].")
    if not all(isinstance(x, int) for x in cle):
        raise ValueError("Tous les éléments doivent être des entiers.")
    a, b, c, d = cle
    det = (a * d - b * c) % TAILLE_ALPHABET
    if det == 0 or pgcd(det, TAILLE_ALPHABET) != 1:
        raise ValueError(f"Matrice 2×2 invalide : det={det} non inversible mod 26.")


def valider_cle_3x3(cle):
    """cle = liste de 9 entiers → matrice 3×3 ligne par ligne."""
    if not isinstance(cle, list) or len(cle) != 9:
        raise ValueError("Clé 3×3 : liste de 9 entiers.")
    if not all(isinstance(x, int) for x in cle):
        raise ValueError("Tous les éléments doivent être des entiers.")
    mat = [[cle[3*i+j] for j in range(3)] for i in range(3)]
    det = determinant_3x3(mat) % TAILLE_ALPHABET
    if det == 0 or pgcd(det, TAILLE_ALPHABET) != 1:
        raise ValueError(f"Matrice 3×3 invalide : det={det} non inversible mod 26.")



#  Préparation du texte


def preparer_texte(texte, taille_bloc):
    """Filtre, met en majuscules et complète avec 'X' si nécessaire."""
    lettres = [c.upper() for c in texte if c.isalpha()]
    reste = len(lettres) % taille_bloc
    if reste != 0:
        lettres.extend(['X'] * (taille_bloc - reste))
    return lettres



#  Chiffrement / Déchiffrement générique


def chiffrer(texte_clair, mat):
    n = len(mat)
    lettres = preparer_texte(texte_clair, n)
    resultat = []
    for i in range(0, len(lettres), n):
        vec = [ord(lettres[i+j]) - ord('A') for j in range(n)]
        chiffre = multiplier_mat_vecteur(mat, vec)
        resultat.extend(chr(v + ord('A')) for v in chiffre)
    return ''.join(resultat)


def dechiffrer(texte_chiffre, mat_inv):
    n = len(mat_inv)
    lettres = preparer_texte(texte_chiffre, n)
    resultat = []
    for i in range(0, len(lettres), n):
        vec = [ord(lettres[i+j]) - ord('A') for j in range(n)]
        dechiffre = multiplier_mat_vecteur(mat_inv, vec)
        resultat.extend(chr(v + ord('A')) for v in dechiffre)
    return ''.join(resultat)



#  Classe Hill (interface publique)


class Hill:


    # ── 2×2 ──────────────────────────────────────────────────

    def chiffrer_2x2(self, texte_clair, cle):
        valider_cle_2x2(cle)
        a, b, c, d = cle
        mat = [[a, b], [c, d]]
        return chiffrer(texte_clair, mat)

    def dechiffrer_2x2(self, texte_chiffre, cle):
        valider_cle_2x2(cle)
        a, b, c, d = cle
        mat = [[a, b], [c, d]]
        mat_inv = inverse_mat_2x2(mat)
        return dechiffrer(texte_chiffre, mat_inv)

    # ── 3×3 ──────────────────────────────────────────────────

    def chiffrer_3x3(self, texte_clair, cle):
        valider_cle_3x3(cle)
        mat = [[cle[3*i+j] for j in range(3)] for i in range(3)]
        return chiffrer(texte_clair, mat)

    def dechiffrer_3x3(self, texte_chiffre, cle):
        valider_cle_3x3(cle)
        mat = [[cle[3*i+j] for j in range(3)] for i in range(3)]
        mat_inv = inverse_mat_3x3(mat)
        return dechiffrer(texte_chiffre, mat_inv)



#  Attaque à clair connu (Known-Plaintext Attack)

#
#  Principe :
#    C = K · P  (mod 26)   ⟹   K = C · P⁻¹  (mod 26)
#
#  Pour Hill n×n on a besoin de n paires (clair, chiffré) linéairement
#  indépendantes.  On construit :
#    P = [p1 | p2 | … | pn]   (matrice n×n, colonnes = blocs clairs)
#    C = [c1 | c2 | … | cn]   (matrice n×n, colonnes = blocs chiffrés)
#  puis  K = C · P⁻¹  mod 26.


def inverser_matrice_mod26(mat, n):
    """Inversion d'une matrice n×n mod 26 par Gauss-Jordan modular."""
    # Copie augmentée [mat | I]
    aug = [mat[i][:] + [int(i == j) for j in range(n)] for i in range(n)]

    for col in range(n):
        # Cherche un pivot inversible
        pivot = None
        for row in range(col, n):
            val = aug[row][col] % TAILLE_ALPHABET
            if val != 0 and pgcd(val, TAILLE_ALPHABET) == 1:
                pivot = row
                break
        if pivot is None:
            raise ValueError("Matrice non inversible mod 26 (système singulier).")
        aug[col], aug[pivot] = aug[pivot], aug[col]

        inv_pivot = inverse_multiplicatif(aug[col][col] % TAILLE_ALPHABET)
        aug[col] = [(inv_pivot * x) % TAILLE_ALPHABET for x in aug[col]]

        for row in range(n):
            if row != col:
                factor = aug[row][col]
                aug[row] = [(aug[row][k] - factor * aug[col][k]) % TAILLE_ALPHABET
                            for k in range(2 * n)]

    return [aug[i][n:] for i in range(n)]


def attaque_clair_connu(clairs, chiffres, n):

    # Convertir en listes de nombres
    if isinstance(clairs, str):
        clairs = [clairs]
    if isinstance(chiffres, str):
        chiffres = [chiffres]

    nums_P = [ord(c) - ord('A') for s in clairs   for c in s if c.isalpha()]
    nums_C = [ord(c) - ord('A') for s in chiffres for c in s if c.isalpha()]

    if len(nums_P) < n * n or len(nums_C) < n * n:
        raise ValueError(f"Il faut au moins {n}×{n}={n*n} paires clair/chiffré.")

    # Prend les n premiers blocs pour construire P et C (matrices n×n)
    # Colonnes = blocs
    P = [[nums_P[b * n + r] for b in range(n)] for r in range(n)]
    C = [[nums_C[b * n + r] for b in range(n)] for r in range(n)]

    # K = C · P⁻¹ mod 26
    P_inv = inverser_matrice_mod26(P, n)
    K = multiplier_mat_mat(C, P_inv, n)
    return K


def afficher_mat(mat, label="Matrice"):
    n = len(mat)
    print(f"\n{label} ({n}×{n}) :")
    for row in mat:
        print("  [" + "  ".join(f"{v:3d}" for v in row) + " ]")



#  Démonstration principale


if __name__ == "__main__":

    separateur = "─" * 60

   
    #  PARTIE 1 – Hill 2×2
   
    print(separateur)
    print("  HILL 2×2")
    print(separateur)

    hill = Hill()
    cle2 = [3, 2, 7, 5]          # det = 15-14 = 1, pgcd(1,26)=1 ✓

    texte_orig   = "HELLO"
    texte_chiff  = hill.chiffrer_2x2(texte_orig, cle2)
    texte_dechif = hill.dechiffrer_2x2(texte_chiff, cle2)

    print(f"Texte original  : {texte_orig}")
    print(f"Texte chiffré   : {texte_chiff}")
    print(f"Texte déchiffré : {texte_dechif}")

    a, b, c, d = cle2
    mat2 = [[a, b], [c, d]]
    mat2_inv = inverse_mat_2x2(mat2)
    afficher_mat(mat2,     "Clé K")
    afficher_mat(mat2_inv, "K⁻¹ mod 26")

   
    #  PARTIE 2 – Hill 3×3
   
    print("\n" + separateur)
    print("  HILL 3×3")
    print(separateur)

    cle3 = [6, 24, 1, 13, 16, 10, 20, 17, 15]   # clé classique des exemples
    # Vérification rapide
    mat3 = [[cle3[3*i+j] for j in range(3)] for i in range(3)]
    det3 = determinant_3x3(mat3) % TAILLE_ALPHABET
    print(f"det(K) mod 26 = {det3}  →  pgcd({det3}, 26) = {pgcd(det3, 26)}")

    texte_orig3   = "ACTEURGAULOIS"
    texte_chiff3  = hill.chiffrer_3x3(texte_orig3, cle3)
    texte_dechif3 = hill.dechiffrer_3x3(texte_chiff3, cle3)

    print(f"Texte original  : {texte_orig3}")
    print(f"Texte chiffré   : {texte_chiff3}")
    print(f"Texte déchiffré : {texte_dechif3}")

    mat3_inv = inverse_mat_3x3(mat3)
    afficher_mat(mat3,     "Clé K (3×3)")
    afficher_mat(mat3_inv, "K⁻¹ mod 26 (3×3)")

   
    #  PARTIE 3 – Attaque à clair connu
   
    print("\n" + separateur)
    print("  ATTAQUE À CLAIR CONNU")
    print(separateur)

    # ── Attaque sur la clé 2×2 ──────────────────────────────
    print("\n[2×2] Clé secrète utilisée pour chiffrer :")
    afficher_mat(mat2, "K réelle")

    # On suppose que l'attaquant connaît 2 blocs clair/chiffré
    clair_connu2   = texte_orig   # "HELLOX" (le texte préparé)
    chiffre_connu2 = texte_chiff

    K2_retrouve = attaque_clair_connu(clair_connu2, chiffre_connu2, n=2)
    afficher_mat(K2_retrouve, "K retrouvée par attaque")

    # Vérification : déchiffrer avec la clé retrouvée
    cle_retrouvee2 = [K2_retrouve[0][0], K2_retrouve[0][1],
                      K2_retrouve[1][0], K2_retrouve[1][1]]
    try:
        test_dechif2 = hill.dechiffrer_2x2(chiffre_connu2, cle_retrouvee2)
        print(f"\nVérification déchiffrement avec K retrouvée : {test_dechif2}")
        print(f"Texte original attendu                       : {preparer_texte(clair_connu2, 2)}")
    except Exception as e:
        print(f"Vérification impossible : {e}")

    # ── Attaque sur la clé 3×3 ──────────────────────────────
    print("\n[3×3] Clé secrète utilisée pour chiffrer :")
    afficher_mat(mat3, "K réelle")

    # Choisir 3 blocs clairs dont la matrice P est inversible mod 26
    # P = [[A,D,G],[B,E,H],[C,F,I]] (colonnes = blocs)
    # On utilise "ABCDEFGHI" → colonnes [0,1,2],[3,4,5],[6,7,8]
    # Matrice P = [[0,3,6],[1,4,7],[2,5,8]] → det = 0, singulière.
    # On prend un triple de blocs choisi pour avoir pgcd(det,26)=1.
    clair_attaque3   = "GYBNQKURP"   # identité mod 26 → P = I (det=1) ✓
    chiffre_attaque3 = hill.chiffrer_3x3(clair_attaque3, cle3)
    print(f"\nBlocs clairs utilisés pour l'attaque   : {clair_attaque3}")
    print(f"Blocs chiffrés correspondants           : {chiffre_attaque3}")

    K3_retrouve = attaque_clair_connu(clair_attaque3, chiffre_attaque3, n=3)
    afficher_mat(K3_retrouve, "K retrouvée par attaque")

    cle_retrouvee3 = [K3_retrouve[i][j] for i in range(3) for j in range(3)]
    try:
        test_dechif3 = hill.dechiffrer_3x3(texte_chiff3, cle_retrouvee3)
        print(f"\nVérification – déchiffrement de '{texte_chiff3}' : {test_dechif3}")
        print(f"Texte original attendu                            : {''.join(preparer_texte(texte_orig3, 3))}")
    except Exception as e:
        print(f"Vérification impossible : {e}")


   