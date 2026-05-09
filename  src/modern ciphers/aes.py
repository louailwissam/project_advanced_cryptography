import sys
import os
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_base import AlgorithmeCryptographique
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Import des finalistes si installés
try:
    from twofish import Twofish

    HAS_TWOFISH = True
except ImportError:
    HAS_TWOFISH = False

try:
    import serpent

    HAS_SERPENT = True
except ImportError:
    HAS_SERPENT = False
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

INV_SBOX = [0] * 256
for i, v in enumerate(SBOX): INV_SBOX[v] = i
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def gmult(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set: a ^= 0x11B
        b >>= 1
    return p & 0xFF


class AESAlgo(AlgorithmeCryptographique):
    def _text_to_matrix(self, text_bytes):
        return [[text_bytes[r + 4 * c] for c in range(4)] for r in range(4)]

    def _matrix_to_text(self, matrix):
        return bytes(matrix[r][c] for c in range(4) for r in range(4))

    def _sub_bytes(self, state, sbox):
        for r in range(4):
            for c in range(4):
                state[r][c] = sbox[state[r][c]]

    def _shift_rows(self, state):
        state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
        state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
        state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]

    def _inv_shift_rows(self, state):
        state[1][0], state[1][1], state[1][2], state[1][3] = state[1][3], state[1][0], state[1][1], state[1][2]
        state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
        state[3][0], state[3][1], state[3][2], state[3][3] = state[3][1], state[3][2], state[3][3], state[3][0]

    def _mix_columns(self, state):
        for c in range(4):
            s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
            state[0][c] = gmult(0x02, s0) ^ gmult(0x03, s1) ^ s2 ^ s3
            state[1][c] = s0 ^ gmult(0x02, s1) ^ gmult(0x03, s2) ^ s3
            state[2][c] = s0 ^ s1 ^ gmult(0x02, s2) ^ gmult(0x03, s3)
            state[3][c] = gmult(0x03, s0) ^ s1 ^ s2 ^ gmult(0x02, s3)

    def _inv_mix_columns(self, state):
        for c in range(4):
            s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
            state[0][c] = gmult(0x0e, s0) ^ gmult(0x0b, s1) ^ gmult(0x0d, s2) ^ gmult(0x09, s3)
            state[1][c] = gmult(0x09, s0) ^ gmult(0x0e, s1) ^ gmult(0x0b, s2) ^ gmult(0x0d, s3)
            state[2][c] = gmult(0x0d, s0) ^ gmult(0x09, s1) ^ gmult(0x0e, s2) ^ gmult(0x0b, s3)
            state[3][c] = gmult(0x0b, s0) ^ gmult(0x0d, s1) ^ gmult(0x09, s2) ^ gmult(0x0e, s3)

    def _add_round_key(self, state, round_key):
        for r in range(4):
            for c in range(4):
                state[r][c] ^= round_key[r][c]

    def _key_expansion(self, key):
        key_symbols = [key[i:i + 4] for i in range(0, 16, 4)]
        for i in range(4, 4 * 11):
            temp = list(key_symbols[i - 1])
            if i % 4 == 0:
                temp = [temp[1], temp[2], temp[3], temp[0]]
                temp = [SBOX[b] for b in temp]
                temp[0] ^= RCON[i // 4]
            key_symbols.append(bytes(a ^ b for a, b in zip(key_symbols[i - 4], temp)))
        return [self._text_to_matrix(b"".join(key_symbols[i * 4: (i + 1) * 4])) for i in range(11)]

    def _encrypt_block(self, block, round_keys):
        state = self._text_to_matrix(block)
        self._add_round_key(state, round_keys[0])
        for i in range(1, 10):
            self._sub_bytes(state, SBOX)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, round_keys[i])
        self._sub_bytes(state, SBOX)
        self._shift_rows(state)
        self._add_round_key(state, round_keys[10])
        return self._matrix_to_text(state)

    def _decrypt_block(self, block, round_keys):
        state = self._text_to_matrix(block)
        self._add_round_key(state, round_keys[10])
        self._inv_shift_rows(state)
        self._sub_bytes(state, INV_SBOX)
        for i in range(9, 0, -1):
            self._add_round_key(state, round_keys[i])
            self._inv_mix_columns(state)
            self._inv_shift_rows(state)
            self._sub_bytes(state, INV_SBOX)
        self._add_round_key(state, round_keys[0])
        return self._matrix_to_text(state)

    def chiffrer(self, texte_clair, cle):
        cle_bytes = cle.encode('utf-8')[:16].ljust(16, b'\0')
        texte_bytes = texte_clair.encode('utf-8')
        pad_len = 16 - (len(texte_bytes) % 16)
        texte_bytes += bytes([pad_len] * pad_len)
        round_keys = self._key_expansion(cle_bytes)
        chiffre = b""
        for i in range(0, len(texte_bytes), 16):
            chiffre += self._encrypt_block(texte_bytes[i:i + 16], round_keys)
        return chiffre.hex()

    def dechiffrer(self, texte_chiffre, cle):
        cle_bytes = cle.encode('utf-8')[:16].ljust(16, b'\0')
        chiffre_bytes = bytes.fromhex(texte_chiffre)
        round_keys = self._key_expansion(cle_bytes)
        clair_bytes = b""
        for i in range(0, len(chiffre_bytes), 16):
            clair_bytes += self._decrypt_block(chiffre_bytes[i:i + 16], round_keys)
        pad_len = clair_bytes[-1]
        return clair_bytes[:-pad_len].decode('utf-8')


# ==========================================
# MENU DE TEST (S'exécute si on lance ce fichier)
# ==========================================
if __name__ == "__main__":
    print("=" * 50)
    print(" TEST TP 2 - AES ET FINALISTES NIST")
    print("=" * 50)

    while True:
        print("\nMenu :")
        print("1. Chiffrement AES-128 (Manuel from scratch)")
        print("2. Effet Avalanche en mode CBC")
        print("3. Benchmark Finalistes NIST (Rijndael, Twofish, Serpent)")
        print("4. Quitter")

        choix = input("\nChoix (1-4) : ")

        if choix == '1':
            algo = AESAlgo()
            msg = input("Texte à chiffrer : ")
            cle = input("Clé (16 caractères = 128 bits) : ")
            if len(cle) != 16:
                print("Erreur: 16 caractères requis.")
            else:
                chiffre = algo.chiffrer(msg, cle)
                print(f"[+] Chiffré (Hex) : {chiffre}")
                print(f"[+] Déchiffré     : {algo.dechiffrer(chiffre, cle)}")

        elif choix == '2':
            cle = os.urandom(16)
            iv_original = bytearray(os.urandom(16))
            iv_modifie = bytearray(iv_original)
            iv_modifie[0] ^= 0x01  # Modifie 1 bit

            message = b"BlocNumeroUn1234BlocNumeroDeux56"

            cipher1 = Cipher(algorithms.AES(cle), modes.CBC(bytes(iv_original)), backend=default_backend())
            c1 = cipher1.encryptor().update(message)

            cipher2 = Cipher(algorithms.AES(cle), modes.CBC(bytes(iv_modifie)), backend=default_backend())
            c2 = cipher2.encryptor().update(message)

            diff1 = sum(bin(a ^ b).count('1') for a, b in zip(c1[:16], c2[:16]))
            diff2 = sum(bin(a ^ b).count('1') for a, b in zip(c1[16:], c2[16:]))

            print(f"\n[Effet Avalanche CBC - 1 bit d'IV modifié]")
            print(f"Différence Bloc 1 : {diff1}/128 bits changés")
            print(f"Différence Bloc 2 : {diff2}/128 bits changés")

        elif choix == '3':
            donnees = os.urandom(1 * 1024 * 1024)  # 1 Mo
            cle = os.urandom(16)
            iv = os.urandom(16)
            print("\nBenchmark sur 1 Mo de données...")

            # AES
            start = time.time()
            Cipher(algorithms.AES(cle), modes.CBC(iv), backend=default_backend()).encryptor().update(donnees)
            print(f"[1] Rijndael (AES) : {time.time() - start:.4f} s")

            # Twofish
            if HAS_TWOFISH:
                T = Twofish(cle)
                start = time.time()
                b"".join(T.encrypt(donnees[i:i + 16]) for i in range(0, len(donnees), 16))
                print(f"[2] Twofish        : {time.time() - start:.4f} s")
            else:
                print("[2] Twofish        : Non installé")

            # Serpent
            if HAS_SERPENT:
                start = time.time()
                b"".join(serpent.encrypt(donnees[i:i + 16], cle) for i in range(0, len(donnees), 16))
                print(f"[3] Serpent        : {time.time() - start:.4f} s")
            else:
                print("[3] Serpent        : Non installé")

        elif choix == '4':
            sys.exit(0)
        else:
            print("Choix invalide.")