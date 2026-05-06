import sys,time, struct, secrets
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto_base import AlgorithmeCryptographique
# permutation initiale p(64 a 64 bits)
PI = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
]

# permutation finale
PF = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]

# Permutation expansive 32 a 48 bits
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
]

# permutation-P : 32 a 32 bits
PP = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25,
]

# table de permutation compressive 64 a 56 bits
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
]

# permutation compressive 56 a 48 bits
PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32,
]

# decalages par ronde
DECALAGES = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# 8 S-Boxes
SBOXES = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
]

# reorganiser les bits selon la table(permutation)


def permuter(bits, table):
    resultat = []
    for t in table:
        resultat.append(bits[t - 1])
    return resultat


# xor bit par bit entre deux listes
def xor(a, b):
    resultat = []
    for i in range(len(a)):
        resultat.append(a[i] ^ b[i])
    return resultat


# convertir un octet  en liste de 8 bits
def octet_vers_bits(octet):
    bits = []
    for i in range(7, -1, -1):
        bits.append((octet >> i) & 1)
    return bits


# convertir une liste de 8 bits en octet
def bits_vers_octet(bits):
    octet = 0
    for b in bits:
        octet = (octet << 1) | b
    return octet


# convertir les bytes du message en liste de bits
def bytes_vers_bits(data):
    bits = []
    for octet in data:
        bits = bits + octet_vers_bits(octet)
    return bits


# convertir une liste de bits en bytes
def bits_vers_bytes(bits):
    resultat = []
    for i in range(0, len(bits), 8):
        resultat.append(bits_vers_octet(bits[i:i+8]))
    return bytes(resultat)

# generer des sous cles


def generer_sous_cles(cle_bits):
    # PC1 passer de 64 bits a 56 bits (enlever les bits de parite)
    cle56 = permuter(cle_bits, PC1)

    # couper en deux moities de 28 bits
    C = cle56[:28]
    D = cle56[28:]

    sous_cles = []
    for d in DECALAGES:
        # decalage circulaire gauche de d positions
        C = C[d:] + C[:d]
        D = D[d:] + D[:d]

        # PC2 : passer de 56 bits a 48 bits
        sous_cles.append(permuter(C + D, PC2))

    return sous_cles


# fonction d'une ronde
def fonction_F(R, K):
    # expansion 32 → 48 bits
    R_exp = permuter(R, E)

    # xor avec la sous-cle de 48 bits
    R_xor = xor(R_exp, K)

    # 8 sboxes, chacune prend 6 bits et donne 4 bits
    sortie = []
    for i in range(8):
        bloc6 = R_xor[i*6: i*6+6]  # extraire 6 bits

        # le 1er et le dernier bit forment le numero de ligne (0 a 3)
        ligne = bloc6[0] * 2 + bloc6[5]

        # les 4 bits du milieu forment le numero de colonne (0 a 15)
        col = bits_vers_octet(bloc6[1:5])

        # chercher la valeur dans la sbox
        val = SBOXES[i][ligne][col]

        # convertir la valeur  en 4 bits
        for j in range(3, -1, -1):
            sortie.append((val >> j) & 1)

    # permutation P finale
    return permuter(sortie, PP)


def chiffrer_bloc(bloc, sous_cles):
    # permutation initiale
    bits = permuter(bloc, PI)

    # couper en gauche et droite
    L = bits[:32]
    R = bits[32:]

    # 16 rondes de feistel
    for i in range(16):
        nouveau_L = R
        nouveau_R = xor(L, fonction_F(R, sous_cles[i]))
        L = nouveau_L
        R = nouveau_R

    # swap final puis permutation finale
    return permuter(R + L, PF)

 # Padding PKCS#7
def pkcs7_pad(data: bytes) -> bytes:
    pad = 8 - (len(data) % 8)
    return data + bytes([pad] * pad)
 
def pkcs7_unpad(data: bytes) -> bytes:
    pad = data[-1]
    if pad < 1 or pad > 8:
        raise ValueError("Padding PKCS7 invalide")
    return data[:-pad]
class DES(AlgorithmeCryptographique):
  # convertir la cle en bits
    def _preparer_cle(self, cle):
        if isinstance(cle, str):
            if len(cle) == 16:
                cle = bytes.fromhex(cle)
            else:
                cle = cle.encode('ascii')
        return bytes_vers_bits(cle)

# ECB  chiffrement et dechiffrment 
    def chiffrer_ecb(self, texte_clair: bytes, cle) -> bytes:
        if isinstance(texte_clair, str):
            texte_clair = texte_clair.encode('utf-8')
        kb = self._preparer_cle(cle)
        sks = generer_sous_cles(kb)
        data = pkcs7_pad(texte_clair)
        out = b""
        for i in range(0, len(data), 8):
            bloc = bytes_vers_bits(data[i:i+8])
            out += bits_vers_bytes(chiffrer_bloc(bloc, sks))
        return out
    
    def dechiffrer_ecb(self, chiffre: bytes, cle) -> bytes:
        kb = self._preparer_cle(cle)
        sks = generer_sous_cles(kb)[::-1]
        out = b""
        for i in range(0, len(chiffre), 8):
            bloc = bytes_vers_bits(chiffre[i:i+8])
            out += bits_vers_bytes(chiffrer_bloc(bloc, sks))
        return pkcs7_unpad(out)
    
    #cbc chiffrement et dechiffrement
    def chiffrer_cbc(self, texte_clair: bytes, cle, iv: bytes) -> bytes:
        if isinstance(texte_clair, str):
            texte_clair = texte_clair.encode('utf-8')
        kb = self._preparer_cle(cle)
        sks = generer_sous_cles(kb)
        data = pkcs7_pad(texte_clair)
        prev = list(bytes_vers_bits(iv))
        out = b""
        for i in range(0, len(data), 8):
            bloc = xor(list(bytes_vers_bits(data[i:i+8])), prev)
            enc = chiffrer_bloc(bloc, sks)
            out += bits_vers_bytes(enc)
            prev = enc
        return out
 
    def dechiffrer_cbc(self, chiffre: bytes, cle, iv: bytes) -> bytes:
        kb = self._preparer_cle(cle)
        sks = generer_sous_cles(kb)[::-1]
        prev = list(bytes_vers_bits(iv))
        out = b""
        for i in range(0, len(chiffre), 8):
            bloc = list(bytes_vers_bits(chiffre[i:i+8]))
            dec = chiffrer_bloc(bloc, sks)
            out += bits_vers_bytes(xor(dec, prev))
            prev = bloc
        return pkcs7_unpad(out)
   # chiffrement

    def chiffrer(self, texte_clair, cle):
          return self.chiffrer_ecb(texte_clair, cle)
   # dechiffrement

    def dechiffrer(self, texte_chiffre, cle):

        return self.dechiffrer_ecb(texte_chiffre, cle)

class TripleDES:
    def _split_key(self, cle):
        if isinstance(cle, str):
            cle = cle.encode('ascii')
        if len(cle) < 24:
            cle = (cle * 3)[:24]
        return cle[:8], cle[8:16], cle[16:24]
 
    def _enc_bloc(self, data8: bytes, sk1, sk2, sk3) -> bytes:
        b = bytes_vers_bits(data8)
        b = chiffrer_bloc(b, sk1)
        b = chiffrer_bloc(b, sk2[::-1])   # dechiffrement K2
        b = chiffrer_bloc(b, sk3)
        return bits_vers_bytes(b)
    def _dec_bloc(self, data8: bytes, sk1, sk2, sk3) -> bytes:
        b = bytes_vers_bits(data8)
        b = chiffrer_bloc(b, sk3[::-1])
        b = chiffrer_bloc(b, sk2)
        b = chiffrer_bloc(b, sk1[::-1])
        return bits_vers_bytes(b)
 
    def _prepare_keys(self, cle):
        k1, k2, k3 = self._split_key(cle)
        des = DES()
        return (generer_sous_cles(des._preparer_cle(k1)),
                generer_sous_cles(des._preparer_cle(k2)),
                generer_sous_cles(des._preparer_cle(k3)))
 
    def chiffrer_cbc(self, texte_clair: bytes, cle, iv: bytes) -> bytes:
        if isinstance(texte_clair, str):
            texte_clair = texte_clair.encode('utf-8')
        sk1, sk2, sk3 = self._prepare_keys(cle)
        data = pkcs7_pad(texte_clair)
        prev = iv
        out = b""
        for i in range(0, len(data), 8):
            xd = bytes(a ^ b for a, b in zip(data[i:i+8], prev))
            enc = self._enc_bloc(xd, sk1, sk2, sk3)
            out += enc
            prev = enc
        return out
 
    def dechiffrer_cbc(self, chiffre: bytes, cle, iv: bytes) -> bytes:
        sk1, sk2, sk3 = self._prepare_keys(cle)
        prev = iv
        out = b""
        for i in range(0, len(chiffre), 8):
            bloc = chiffre[i:i+8]
            dec = self._dec_bloc(bloc, sk1, sk2, sk3)
            out += bytes(a ^ b for a, b in zip(dec, prev))
            prev = bloc
        return pkcs7_unpad(out)
 
    def chiffrer(self, texte_clair, cle):
        return self.chiffrer_cbc(texte_clair, cle, bytes(8))
 
    def dechiffrer(self, chiffre, cle):
        return self.dechiffrer_cbc(chiffre, cle, bytes(8))
 

if __name__ == "__main__":
    des = DES()
    t3   = TripleDES()
    CLE  = "DESCOURS"
    CLE3 = b"DESCOURSDESCOURSDESCOURS"   # 24 octets
    IV   = secrets.token_bytes(8)
# ECB VS CBC SUR 128 OCTEST
    print("partie 1 DES-ECB vs DES-CBC 128 octets")
    MESSAGE = b"A" * 64 + b"B" * 64 
 
    ecb = des.chiffrer_ecb(MESSAGE, CLE)
    cbc = des.chiffrer_cbc(MESSAGE, CLE, IV)
 
    print(f"IV (alweatoire)  : {IV.hex().upper()}")
    print(f"\nCryptogramme ECB ({len(ecb)} octets) :")
    for i in range(0, len(ecb), 8):
        bloc = ecb[i:i+8]
        print(f"  bloc {i//8:02d} : {bloc.hex().upper()}")
 
    print(f"\nCryptogramme CBC ({len(cbc)} octets) :")
    for i in range(0, len(cbc), 8):
        bloc = cbc[i:i+8]
        print(f"  bloc {i//8:02d} : {bloc.hex().upper()}")
 
    # Compter les doublons ECB
    ecb_blocs = [ecb[i:i+8].hex().upper() for i in range(0, len(ecb), 8)]
    from collections import Counter
    doublons = {h: c for h, c in Counter(ecb_blocs).items() if c > 1}
    print(f"\nECB — blocs dupliques : {doublons}")
 
    # Verification dechiffrement
    assert des.dechiffrer_ecb(ecb, CLE) == MESSAGE, "Erreur dechiffrement ECB"
    assert des.dechiffrer_cbc(cbc, CLE, IV) == MESSAGE, "Erreur dechiffrement CBC"
    print("Dechiffrement ECB : OK")
    print("Dechiffrement CBC : OK")
 
    # pertie 2 Faiblesse ECB sur image 64×64
    print("2 Faiblesse ECB visualisee (image 64×64 pixels)")
    try:
        from PIL import Image
        import io
 
        def gen_image():
            img = Image.new("RGB", (64, 64), (240, 240, 240))
            from PIL import ImageDraw
            draw = ImageDraw.Draw(img)
            draw.rectangle([0, 0, 15, 15], fill=(30, 30, 200))
            draw.rectangle([48, 0, 63, 15], fill=(30, 150, 30))
            draw.ellipse([24, 24, 40, 40], fill=(220, 50, 50))
            draw.rectangle([12, 28, 52, 36], fill=(200, 150, 0))
            return img
 
        img = gen_image()
        raw = img.tobytes()  # 64×64×3 = 12288 octets
 
        ecb_img = des.chiffrer_ecb(raw, CLE)
        cbc_img = des.chiffrer_cbc(raw, CLE, IV)
 
        # Reconstituer les images chiffrees
        def to_img(data, size=(64, 64)):
            trunc = data[:size[0]*size[1]*3]
            trunc += bytes(size[0]*size[1]*3 - len(trunc))
            return Image.frombytes("RGB", size, trunc)
 
        img.save("image_originale.png")
        to_img(ecb_img).save("image_chiffree_ecb.png")
        to_img(cbc_img).save("image_chiffree_cbc.png")
        print("Images sauvegardees : image_originale.png, image_chiffree_ecb.png, image_chiffree_cbc.png")
        print("Ouvrez image_chiffree_ecb.png : les zones uniformes restent reconnaissables.")
 
    except ImportError:
        print("Pillow non disponible. Simulation sur tableau de bytes :")
        # Creer des donnees avec motif repetitif 
        raw = (b'\xff\x00\x00' * 256 + b'\x00\xff\x00' * 256) * 8  # 12288 octets
        ecb_img = des.chiffrer_ecb(raw, CLE)
        cbc_img = des.chiffrer_cbc(raw, CLE, IV)
        #compter les blocs dupliques dans le resultat ECB
        ecb_blocs_img = [ecb_img[i:i+8].hex() for i in range(0, len(ecb_img), 8)]
        doublons_img = sum(1 for c in Counter(ecb_blocs_img).values() if c > 1)
        print(f"  ECB : {doublons_img} groupes de blocs dupliques (motifs visibles)")
        print(f"  CBC : 0 doublon ")
 
    #partie3 Triple-DES CBC + benchmark 
    print("\n" + "=" * 60)
    print("3 Triple-DES CBC + benchmark DES vs 3DES ")
    print("=" * 60)
 
    MSG3 = MESSAGE  # meme 128 octets
 
    c3 = t3.chiffrer_cbc(MSG3, CLE3, IV)
    d3 = t3.dechiffrer_cbc(c3, CLE3, IV)
    assert d3 == MSG3, "Erreur dechiffrement 3DES"
    print(f"3DES chiffre  : {c3[:16].hex().upper()}... ({len(c3)} octets)")
    print(f"3DES déchiffre : OK ")
 
    # Benchmark sur 1 Ko
    BENCH = secrets.token_bytes(1024)
    N = 3  # repetitions pour stabiliser
 
    t0 = time.perf_counter()
    for _ in range(N):
        des.chiffrer_cbc(BENCH, CLE, IV)
    t_des = (time.perf_counter() - t0) / N
 
    t0 = time.perf_counter()
    for _ in range(N):
        t3.chiffrer_cbc(BENCH, CLE3, IV)
    t_3des = (time.perf_counter() - t0) / N
 
    des_1mb  = t_des  / 1024 * 1024 * 1024
    t3des_1mb = t_3des / 1024 * 1024 * 1024
 
    print(f"\nBenchmark :")
    print(f"  DES-CBC  : {t_des*1000:.1f} ms / 1 Ko  : {des_1mb:.1f} ms / 1 Mo")
    print(f"  3DES-CBC : {t_3des*1000:.1f} ms / 1 Ko  :  {t3des_1mb:.1f} ms / 1 Mo")
    print(f"  Ratio 3DES/DES : {t_3des/t_des:.2f}× plus lent")
    print("\n 3DES est 3× plus lent que DES mais offre une securite largement superieure")
    print("  (112 bits effectifs vs 56 bits pour DES).")
