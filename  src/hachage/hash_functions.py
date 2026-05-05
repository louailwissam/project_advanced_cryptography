import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import struct
import time
import hmac
import hashlib
from crypto_base import AlgorithmeCryptographique

# exercice 4.1
class MD5Demo:
    # encodage et hachage
    def calculer(self, data: bytes) -> str:
        if isinstance(data, str):
            data = data.encode()
        return hashlib.md5(data).hexdigest()

    def demo_5_messages(self):
        print("MD5 — 5 messages de tailles differentes")
        cas = [
            ("Chaine vide",  b""),
            ("1 octet",      b"A"),
            ("1 Ko",         os.urandom(1024)),
            ("1 Mo",         os.urandom(1024 * 1024)),
            ("Fichier bin",  bytes(range(256)) * 4),
        ]
        for label, data in cas:
            h = self.calculer(data)
            bits = len(h) * 4
            # verification
            assert bits == 128
            print(f"{label:12s} , {bits:3d} bits, {h}")
        print("\ntous les hashs MD5 ont en sortie 128 bits")

    def effet_avalanche(self):
        print("   MD5 — Effet Avalanche (1 bit modifie)")

        messages = [b"Hello World", b"A" * 100, os.urandom(500)]
        for msg in messages:
            h1 = hashlib.md5(msg).digest()

            # Flipper le bit 0 du premier octet
            msg2 = bytearray(msg)
            msg2[0] ^= 0x01
            h2 = hashlib.md5(bytes(msg2)).digest()

            bits_diff = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(h1, h2))
            total = len(h1) * 8
            taux = bits_diff / total * 100

            print(f"\n  Message ({len(msg)} octets) :")
            print(f"Hash original : {h1.hex()}")
            print(f"Hash modifie  : {h2.hex()}")
            print(f"Bits differents : {bits_diff}/{total}  ({taux:.1f} %)")

# exercice 4.2


class SHA256Manuel:
    # 64 constantes predefinies(premiers 32 bits des racines cubiques des 64 premiers nombres premiers)
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]

    # Valeurs initiales de hachage (8) (racines carrees des 8 premiers nombres premiers)
    H0 = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]

    @staticmethod
    # rotation circulair a droite sur 32 bits
    def _rotr(x: int, n: int) -> int:
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
    # ajoute 1 puis des 0 (longueur sur 64 bits))

    @staticmethod
    def _padding(msg: bytes) -> bytes:
        L = len(msg) * 8  # longueur en bits
        msg += b'\x80'    # ajouter le bit '1'

    # Calculer combien de zeros ajouter pour atteindre 56 octets
    # La formule (56 - (len(msg) % 64)) % 64
        padding_length = (56 - (len(msg) % 64)) % 64
        msg += b'\x00' * padding_length

    # Ajouter la longueur sur 64 bits
        msg += struct.pack('>Q', L)

        return msg

    def hash(self, msg: bytes) -> str:
        if isinstance(msg, str):
            msg = msg.encode()

        msg = self._padding(msg)
        H = list(self.H0)

        # traitement de chaque bloc de 512 bits (64 octets)
        for i in range(0, len(msg), 64):
            bloc = msg[i:i+64]

            # expansion du message : W[0..63]
            W = list(struct.unpack('>16I', bloc)) + [0] * 48
            for j in range(16, 64):
                s0 = self._rotr(
                    W[j-15], 7) ^ self._rotr(W[j-15], 18) ^ (W[j-15] >> 3)
                s1 = self._rotr(
                    W[j-2], 17) ^ self._rotr(W[j-2], 19) ^ (W[j-2] >> 10)
                W[j] = (W[j-16] + s0 + W[j-7] + s1) & 0xFFFFFFFF

            # 64 tours de compression
            a, b, c, d, e, f, g, h = H
            for j in range(64):
                S1 = self._rotr(e, 6) ^ self._rotr(e, 11) ^ self._rotr(e, 25)
                ch = (e & f) ^ (~e & g)
                T1 = (h + S1 + ch + self.K[j] + W[j]) & 0xFFFFFFFF
                S0 = self._rotr(a, 2) ^ self._rotr(a, 13) ^ self._rotr(a, 22)
                maj = (a & b) ^ (a & c) ^ (b & c)
                T2 = (S0 + maj) & 0xFFFFFFFF
                h = g
                g = f
                f = e
                e = (d + T1) & 0xFFFFFFFF
                d = c
                c = b
                b = a
                a = (T1 + T2) & 0xFFFFFFFF

            H = [(H[i] + v) & 0xFFFFFFFF for i,
                 v in enumerate([a, b, c, d, e, f, g, h])]

        return ''.join(f'{v:08x}' for v in H)

    def valider_contre_hashlib(self):
        print("   SHA-256 MANUEL — Validation contre hashlib (10 vecteurs)")

        vecteurs = [
            b"",
            b"abc",
            b"hello world",
            b"SHA-256 test",
            b"cryptographie tp project",
            b"\x00",
            b"\xff" * 64,
            os.urandom(100),
            os.urandom(1000),
            b"Cryptographie Appliquee TP4",
        ]

        tous_ok = True
        for i, v in enumerate(vecteurs):
            ref = hashlib.sha256(v).hexdigest()
            manuel = self.hash(v)
            ok = ref == manuel
            if not ok:
                tous_ok = False
            print(f"  [{i+1:2d}] {'ok' if ok else 'ok'} "
                  f"{v[:20]}{'...' if len(v) > 20 else ''}")

        print(
            f"\n  Resultat global : {'tous est correct' if tous_ok else 'erreur detectee'}")

    def verifier_integrite_fichier(self, donnees: bytes, hash_officiel: str):
        print("   SHA-256 verification d'integrite de fichier")
        hash_local = hashlib.sha256(donnees).hexdigest()
        ok = hmac.compare_digest(hash_local, hash_officiel)
        print(f"  Hash officiel : {hash_officiel}")
        print(f"  Hash local    : {hash_local}")
        print(f"  Resultat      : {'fichier integre' if ok else 'CORROMPU'}")
        return ok

# exercice 4.3


class ComparaisonHash:

    ALGOS = {
        'MD5': ('md5',    128),
        'SHA-256': ('sha256', 256),
        'SHA-512': ('sha512', 512),
    }

    def comparer_sur_message(self, msg: bytes = b"Cryptographie Appliquee"):
        print(" COMPARAISON MD5 / SHA-256 / SHA-512")
        print(f"  Message : {msg.decode(errors='replace')!r}\n")

        for nom, (algo, bits) in self.ALGOS.items():
            t0 = time.perf_counter()
            h = hashlib.new(algo, msg).hexdigest()
            dt = (time.perf_counter() - t0) * 1e6
            print(f"  {nom:8s} | {bits:3d} bits | {dt:6.1f} µs | {h[:48]}...")

        # Effet avalanche pour chacun
        print(f"\nEffet Avalanche (1 bit modifie)")
        msg2 = bytearray(msg)
        msg2[0] ^= 1
        msg2 = bytes(msg2)
        for nom, (algo, bits) in self.ALGOS.items():
            h1 = bytes.fromhex(hashlib.new(algo, msg).hexdigest())
            h2 = bytes.fromhex(hashlib.new(algo, msg2).hexdigest())
            diff = sum(bin(a ^ b).count('1') for a, b in zip(h1, h2))
            print(
                f"  {nom:8s} | {diff}/{bits} bits differents ({diff/bits*100:.1f} %)")

    def benchmark_100mo(self):
        print("   BENCHMARK   ")
        donnees = os.urandom(100 * 1024 * 1024)   # 100 Mo
        resultats = {}
        for nom, (algo, _) in self.ALGOS.items():
            t0 = time.perf_counter()
            hashlib.new(algo, donnees).digest()
            dt = time.perf_counter() - t0
            debit = 100 / dt
            resultats[nom] = debit
            print(f"  {nom:8s} | {dt:.3f} s | {debit:.1f} Mo/s")

        plus_rapide = max(resultats, key=resultats.get)
        plus_lent = min(resultats, key=resultats.get)
        print(
            f"\n  Plus rapide : {plus_rapide} ({resultats[plus_rapide]:.1f} Mo/s)")
        print(
            f"  Plus lent   : {plus_lent}   ({resultats[plus_lent]:.1f} Mo/s)")


if __name__ == "__main__":

    print("\nexercice 4.1")
    md5 = MD5Demo()
    md5.demo_5_messages()
    md5.effet_avalanche()

    print("\n exercice 4.2")
    sha = SHA256Manuel()
    sha.valider_contre_hashlib()
    # Simuler une archive et sa verification
    archive = os.urandom(512 * 1024)
    hash_ref = hashlib.sha256(archive).hexdigest()
    sha.verifier_integrite_fichier(archive, hash_ref)
    # Fichier corrompu
    archive_corrompu = bytearray(archive)
    archive_corrompu[0] ^= 1
    sha.verifier_integrite_fichier(bytes(archive_corrompu), hash_ref)

    print("\nexercice 4.3")
    comp = ComparaisonHash()
    comp.comparer_sur_message()
    comp.benchmark_100mo()
