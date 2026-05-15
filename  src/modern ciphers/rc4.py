
import os
import random
import collections
import string


#  PARTIE 1 – RC4 : KSA + PRGA


def ksa(cle: bytes) -> list[int]:

    L = len(cle)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + cle[i % L]) % 256
        S[i], S[j] = S[j], S[i]   # échange dans S
    return S


def prga(S: list[int], longueur: int) -> list[int]:

    S = S[:]          # copie : ne pas modifier l'état KSA de référence
    i = j = 0
    keystream = []
    for _ in range(longueur):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream.append(S[(S[i] + S[j]) % 256])
    return keystream


def rc4_keystream(cle: bytes, longueur: int) -> list[int]:
    return prga(ksa(cle), longueur)


def rc4_chiffrer(texte: bytes, cle: bytes) -> bytes:
    ks = rc4_keystream(cle, len(texte))
    return bytes(t ^ k for t, k in zip(texte, ks))


def rc4_dechiffrer(chiffre: bytes, cle: bytes) -> bytes:
    return rc4_chiffrer(chiffre, cle)   # XOR symétrique



#  Classe RC4 (interface haut niveau)


class RC4:

    def _valider_cle(self, cle: str):
        if not isinstance(cle, str):
            raise ValueError("La clé doit être une chaîne de caractères.")
        if not (1 <= len(cle) <= 256):
            raise ValueError("La clé doit contenir entre 1 et 256 caractères.")

    def chiffrer(self, texte_clair: str, cle: str) -> str:
        self._valider_cle(cle)
        sortie = rc4_chiffrer(texte_clair.encode(), cle.encode())
        return sortie.hex()

    def dechiffrer(self, texte_chiffre_hex: str, cle: str) -> str:
        self._valider_cle(cle)
        chiffre = bytes.fromhex(texte_chiffre_hex)
        return rc4_dechiffrer(chiffre, cle.encode()).decode()



#  PARTIE 2 – Vulnérabilité WEP (attaque FMS / IV faibles)

#  Dans WEP, la clé de chiffrement est : IV (3 octets) || clé_WEP
#  L'IV est transmis EN CLAIR dans chaque paquet.
#
#  L'attaque FMS (Fluhrer-Mantin-Shamir, 2001) montre que pour des
#  IV de la forme  (A+3, N-1, X)  — appelés "IV faibles" —
#  le PREMIER octet du keystream révèle directement un octet de la clé.
#
#  Démonstration simplifiée :
#  ─────────────────────────
#  On fixe la clé secrète WEP et on génère des IV commençant par
#  0x00, 0x01, 0x02… On observe que le 1er octet du keystream est
#  corrélé à la clé : sa distribution n'est PAS uniforme sur [0,255].


def demo_vulnerabilite_wep(cle_wep: bytes, nb_iv: int = 16):

    print("\n" + "═" * 62)
    print("  VULNÉRABILITÉ WEP — IV FAIBLES (FMS attack)")
    print("═" * 62)
    print(f"  Clé WEP secrète (hex) : {cle_wep.hex().upper()}")
    print(f"  Longueur clé WEP      : {len(cle_wep)} octets")
    print()
    print(f"  {'IV (hex)':<14}  {'Clé totale (IV||WEP) hex':<28}  "
          f"{'KS[0]':>6}  Observation")
    print("  " + "─" * 68)

    # IV faibles de la forme (3, 255, X) — formulaire FMS classique
    # Pour simplifier on fait varier X = 0..nb_iv-1
    resultats = []
    for x in range(nb_iv):
        iv = bytes([3, 255, x])          # IV faible canonique FMS
        cle_totale = iv + cle_wep        # WEP concatène IV en tête
        S = ksa(cle_totale)
        ks0 = prga(S, 1)[0]             # 1er octet du keystream

        # Prédiction FMS : ks0 devrait être proche de
        # (S[1] + S[S[1]]) … simplifié ici en observant la valeur brute
        observation = (
            "← = clé[0] XOR 0 probable"
            if ks0 == cle_wep[0]
            else f"(valeur {ks0})"
        )
        resultats.append(ks0)
        print(f"  {iv.hex().upper():<14}  {cle_totale.hex().upper():<28}  "
              f"{ks0:>6}  {observation}")

    # Fréquence : combien de fois KS[0] == cle_wep[0] ?
    hits = sum(1 for v in resultats if v == cle_wep[0])
    print()
    print(f"  KS[0] == cle_wep[0] ({cle_wep[0]}) dans {hits}/{nb_iv} cas "
          f"({100*hits//nb_iv} %)")
    print(f"  Attendu aléatoire : ~{100//256} %  →  biais visible !")
    print()
    print("  Explication :")
    print("  ─────────────")
    print("  Pour un IV de la forme (3, 255, X), après KSA les 3 premiers")
    print("  échanges laissent S dans un état prévisible : S[1] = cle_wep[0]")
    print("  avec probabilité ≈ 1/256 × facteur d'amplification FMS.")
    print("  En collectant ~60 000 paquets WEP, chaque octet de la clé")
    print("  peut être retrouvé avec ~95 % de succès (aircrack-ng, 2005).")



#  Démonstration supplémentaire : IV croissants 0x00…


def demo_iv_croissants(cle_wep: bytes, nb_iv: int = 8):
    """
    Montre l'évolution du keystream complet pour des IV = 0x00…0x00,
    0x00…0x01, etc. : chaque paquet WEP a un keystream différent,
    mais les IV sont trivials et transmis en clair → l'attaquant
    peut reconstruire tous les keystreamss dès qu'il connaît la clé.
    """
    print("\n" + "─" * 62)
    print("  IV CROISSANTS — keystream par paquet")
    print("─" * 62)
    print(f"  {'IV':<10}  {'Keystream (16 premiers octets)'}")
    print("  " + "─" * 54)
    for n in range(nb_iv):
        iv = n.to_bytes(3, 'big')
        cle_totale = iv + cle_wep
        ks = rc4_keystream(cle_totale, 16)
        ks_hex = ' '.join(f'{b:02x}' for b in ks)
        print(f"  {iv.hex().upper():<10}  {ks_hex}")
    print()
    print("  → Chaque paquet a un keystream unique, mais l'IV en clair")
    print("    permet à l'attaquant de TRIER les paquets par IV faible.")



#  PARTIE 3 – Biais statistiques (RC4 bias)
#  Le biais le plus célèbre de RC4 : le 2e octet du keystream
#  vaut 0 avec une probabilité ≈ 2/256 (au lieu de 1/256).
#  Ce doublement est dû à la structure du PRGA au pas i=2 :
#    • i=2, j=S[2] après KSA
#    • Si S[2] = 0, le 2e octet émis = S[S[2]+S[j]] = S[S[0]] = S[0]
#    •  … et S[0] = 0 souvent après KSA (biais propre au KSA).
#  Ce biais s'accumule sur des millions de paquets TLS et permet
#  de récupérer des octets de plaintext (attaque BEAST/RC4 2013-2015).


def demo_biais_statistiques(nb_keystreams: int = 10_000, longueur_ks: int = 32):

    print("\n" + "═" * 62)
    print("  BIAIS STATISTIQUES RC4")
    print("═" * 62)
    print(f"  {nb_keystreams:,} keystreams générés, clés aléatoires 16 octets")
    print()

    # Collecte
    compteurs = [collections.Counter() for _ in range(longueur_ks)]
    for _ in range(nb_keystreams):
        cle = os.urandom(16)
        ks  = rc4_keystream(cle, longueur_ks)
        for pos, octet in enumerate(ks):
            compteurs[pos][octet] += 1

    attendu = nb_keystreams / 256   # fréquence uniforme théorique

    # ── Affichage position par position 
    for pos in [0, 1, 2, 3]:
        ctr = compteurs[pos]
        val_biais = max(ctr, key=ctr.get)   # valeur la plus fréquente
        freq_max  = ctr[val_biais]
        ratio     = freq_max / attendu

        print(f"  Position {pos} (octet n°{pos+1} du keystream)")
        print(f"  ├─ Valeur la plus fréquente : {val_biais} "
              f"(freq={freq_max}, ratio={ratio:.3f}×)")
        print(f"  ├─ Fréquence attendue (uniforme) : {attendu:.1f}")
        biais_pct = 100 * (freq_max - attendu) / attendu
        print(f"  └─ Biais : +{biais_pct:.1f} %")
        print()

    # ── Histogramme ASCII du 2e octet (position 1) ───────────
    print("  Histogramme — 2e octet du keystream (position 1)")
    print("  Valeur 0 est sur-représentée (RC4 bias classique)")
    print()
    ctr1 = compteurs[1]
    # Affiche les 16 premières valeurs
    bar_scale = 40 / max(ctr1.values())
    for v in range(16):
        cnt  = ctr1[v]
        barre = "█" * int(cnt * bar_scale)
        marqueur = " ← BIAIS !" if v == 0 and cnt > attendu * 1.5 else ""
        print(f"  {v:3d} | {barre:<40} {cnt:5d}{marqueur}")
    print(f"  {'…':>4}")
    print()
    print(f"  Ligne uniforme attendue ≈ {attendu:.0f} occurrences")
    print()





#  Programme principal


if __name__ == "__main__":

    sep = "═" * 62

  
    #  PARTIE 1 – Démo chiffrement / déchiffrement
  
    print(sep)
    print("  RC4 — CHIFFREMENT / DÉCHIFFREMENT")
    print(sep)

    rc4 = RC4()
    cle_demo = "SECRET"
    texte     = "Hello, World! — RC4 en action."

    chiffre   = rc4.chiffrer(texte, cle_demo)
    dechiffre = rc4.dechiffrer(chiffre, cle_demo)

    print(f"  Clé              : {cle_demo}")
    print(f"  Texte original   : {texte}")
    print(f"  Texte chiffré    : {chiffre}")
    print(f"  Texte déchiffré  : {dechiffre}")
    print()

    # Afficher les 16 premiers octets du keystream
    ks_demo = rc4_keystream(cle_demo.encode(), 16)
    print("  KSA + PRGA — 16 premiers octets du keystream :")
    print("  " + " ".join(f"{b:02x}" for b in ks_demo))
    print()
    print("  Propriété XOR symétrique : chiffrer(chiffré, clé) = clair")
    double = rc4.dechiffrer(rc4.chiffrer(texte, cle_demo), cle_demo)
    print(f"  Vérification : {double}")

  
    #  PARTIE 2 – Vulnérabilité WEP
  
    cle_wep = b"\xAB\xCD\xEF\x01\x23"    # clé WEP 40 bits (5 octets)
    demo_vulnerabilite_wep(cle_wep, nb_iv=20)
    demo_iv_croissants(cle_wep, nb_iv=6)

  
    #  PARTIE 3 – Biais statistiques
  
    demo_biais_statistiques(nb_keystreams=10_000, longueur_ks=32)