import sys
import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


class RSA:
    def __init__(self, key_size: int = 2048):
        if key_size not in (512, 1024, 2048):
            raise ValueError("key_size doit être 512, 1024 ou 2048.")
        self.key_size = key_size
        self.cle_privee = None
        self.cle_publique = None
        self._generer_cles()

    def _generer_cles(self):
        print(f"[RSA-{self.key_size}] Génération des clés...", end=" ", flush=True)
        t = time.time()
        try:
            self.cle_privee = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size,
                backend=default_backend()
            )
            self.cle_publique = self.cle_privee.public_key()
            print(f"({time.time()-t:.3f}s)")
        except Exception as e:
            print(f"ÉCHEC: {e}")

    def chiffrer(self, texte_clair, cle=None) -> bytes:
        if isinstance(texte_clair, str):
            texte_clair = texte_clair.encode()
        
        # Utiliser PKCS1v15 pour RSA-512, OAEP pour les autres
        if self.key_size == 512:
            padding_algo = padding.PKCS1v15()
        else:
            padding_algo = padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        
        return self.cle_publique.encrypt(texte_clair, padding_algo)

    def dechiffrer(self, texte_chiffre: bytes, cle=None) -> bytes:
        if self.key_size == 512:
            padding_algo = padding.PKCS1v15()
        else:
            padding_algo = padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        
        return self.cle_privee.decrypt(texte_chiffre, padding_algo)

    def exporter_cle_publique(self) -> str:
        return self.cle_publique.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def exporter_cle_privee(self) -> str:
        return self.cle_privee.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

    def demo_512_1024_2048(self):
        print("   RSA — Comparaison 512 / 1024 / 2048 bits")
        
        # Taille des messages adaptée à chaque clé
        test_cases = [
            (512, 32, "PKCS1v15 (32 octets)"),
            (1024, 32, "32 octets"),
            (2048, 32, "32 octets")
        ]
        
        for bits, msg_size, padding_type in test_cases:
            try:
                r = RSA(bits)
                message = os.urandom(msg_size)
                print(f"\nMessage ({len(message)} octets) : {message.hex()[:32]}...")
                
                # Chiffrement
                t0 = time.time()
                c = r.chiffrer(message)
                t1 = time.time()
                
                # Déchiffrement
                m = r.dechiffrer(c)
                t2 = time.time()
                
                ok = (m == message)
                print(f"RSA-{bits:4d} | padding={padding_type:15} | "
                      f"chiffré={len(c):3d} o | "
                      f"chiffre={1000*(t1-t0):.1f}ms | "
                      f"déchiffre={1000*(t2-t1):.1f}ms | "
                      f"{'OK' if ok else 'ERREUR'}")
            except Exception as e:
                print(f"RSA-{bits:4d} | ÉCHEC: {str(e)[:60]}")

        print("\nExport RSA-2048 — clé publique PEM")
        print(self.exporter_cle_publique()[:64] + "...")


class ChiffrementHybride:
    def __init__(self, rsa_instance: RSA):
        self.rsa = rsa_instance

    def chiffrer_fichier(self, donnees: bytes):
        print("   CHIFFREMENT HYBRIDE RSA + AES-256-GCM")
        print(f"   Taille du fichier : {len(donnees)/1024:.0f} Ko\n")

        cle_aes = os.urandom(32)
        iv = os.urandom(12)

        t0 = time.time()
        cle_aes_chiffree = self.rsa.chiffrer(cle_aes)
        t_rsa = time.time() - t0
        print(f"[RSA]  Clé AES chiffrée : {len(cle_aes_chiffree)} octets  ({t_rsa*1000:.2f} ms)")

        t0 = time.time()
        cipher = Cipher(algorithms.AES(cle_aes), modes.GCM(iv), backend=default_backend())
        enc = cipher.encryptor()
        donnees_chiffrees = enc.update(donnees) + enc.finalize()
        tag = enc.tag
        t_aes = time.time() - t0
        print(f"[AES]  Données chiffrées : {len(donnees_chiffrees)/1024:.0f} Ko  ({t_aes*1000:.2f} ms)")

        print(f"\n   Rapport RSA/AES : RSA est {t_rsa/t_aes:.2f}× plus lent qu'AES")
        print(" Raison d'être du chiffrement hybride : AES pour les données,\n"
              "     RSA uniquement pour transporter la clé AES.\n")

        return cle_aes_chiffree, iv, donnees_chiffrees, tag, cle_aes

    def dechiffrer_fichier(self, cle_aes_chiffree, iv, donnees_chiffrees, tag):
        cle_aes = self.rsa.dechiffrer(cle_aes_chiffree)
        cipher = Cipher(algorithms.AES(cle_aes), modes.GCM(iv, tag), backend=default_backend())
        dec = cipher.decryptor()
        return dec.update(donnees_chiffrees) + dec.finalize()


if __name__ == "__main__":
    r = RSA(2048)

    print("\n─── PARTIE 1 : RSA 512 / 1024 / 2048 ───")
    r.demo_512_1024_2048()

    print("\n─── PARTIE 2 : Chiffrement hybride RSA + AES ───")
    hybrid = ChiffrementHybride(r)
    fichier_test = os.urandom(1024 * 1024)
    cle_c, iv, data_c, tag, _ = hybrid.chiffrer_fichier(fichier_test)
    data_d = hybrid.dechiffrer_fichier(cle_c, iv, data_c, tag)
    assert data_d == fichier_test, "Déchiffrement échoué"
    print(f"\nFichier déchiffré correctement ({len(data_d)/1024:.0f} Ko)")