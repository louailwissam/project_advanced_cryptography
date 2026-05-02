import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def exercice_benchmark_aes():
    """ TP 2 - Exercice 2.3.4 : Comparaison des performances AES """
    print("\n--- BENCHMARK DES FINALISTES AES SUR 10 Mo ---")
    donnees = os.urandom(10 * 1024 * 1024)  # 10 Mo
    iv = os.urandom(16)

    for taille_cle in [16, 24, 32]:  # 128, 192, 256 bits
        cle = os.urandom(taille_cle)
        cipher = Cipher(algorithms.AES(cle), modes.CBC(iv), backend=default_backend())

        start = time.time()
        enc = cipher.encryptor()
        enc.update(donnees) + enc.finalize()
        duree = time.time() - start

        debit = 10 / duree
        print(f"AES-{taille_cle * 8} bits -> Temps: {duree:.4f}s | Débit: {debit:.2f} Mo/s")


if __name__ == "__main__":
    exercice_benchmark_aes()