from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key, ECDH
import sys
import os
import socket
import threading
import json
import hashlib
import time
import struct
import random
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def deriver_cle_aes(secret: bytes) -> bytes:
    # SHA-256(secret ECDH) = cle AES-256 de 32 octets
    return hashlib.sha256(secret).digest()


def aes_gcm_chiffrer(cle: bytes, plaintext: bytes) -> tuple:
    # chiffrement AES-256-GCM.
    # retourne (iv 12 octets, ciphertext, tag 16 octets)Un IV aleatoire frais est genere a chaque appel
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(cle), modes.GCM(iv),
                    backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    return iv, ct, enc.tag


def aes_gcm_dechiffrer(cle: bytes, iv: bytes, ct: bytes, tag: bytes) -> bytes:
    # dechiffrement AES-256-GCM avec verification du tag leve une exception si le message a ete modifie.
    cipher = Cipher(algorithms.AES(cle), modes.GCM(
        iv, tag), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(ct) + dec.finalize()


def envoyer_json(sock: socket.socket, obj: dict):
    # serialise obj en JSON et l'envoie avec un header 4 octets (longueur)
    data = json.dumps(obj).encode('utf-8')
    sock.sendall(struct.pack('>I', len(data)) + data)


def recevoir_json(sock: socket.socket) -> dict:
    # lit le header 4 octets puis le JSON de la longueur indiquee
    raw_len = _recv_exact(sock, 4)
    if not raw_len:
        return None
    n = struct.unpack('>I', raw_len)[0]
    data = _recv_exact(sock, n)
    return json.loads(data.decode('utf-8'))


def _recv_exact(sock, n: int) -> bytes:
    # boucle sur sock.recv() jusqu'a avoir exactement n octets
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b''
        buf += chunk
    return buf
# cote serveur


def _handshake_serveur(conn, ecdsa_priv, ecdsa_pub, label="") -> bytes:
    # genere paire ECDH ephemere
    ecdh_priv = generate_private_key(SECP256R1(), default_backend())
    ecdh_pub = ecdh_priv.public_key()
    pub_bytes = ecdh_pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Signe la cle publique ECDH avec ECDSA
    signature = ecdsa_priv.sign(pub_bytes, ECDSA(hashes.SHA256()))
    ecdsa_pub_bytes = ecdsa_pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Envoie {ecdh_pub, signature, ecdsa_pub}
    envoyer_json(conn, {
        'ecdh_pub': pub_bytes.decode(),
        'signature': signature.hex(),
        'ecdsa_pub': ecdsa_pub_bytes.decode()
    })
    # eecoit la cle ECDH du client (+ verifie sa signature si presente)
    data = recevoir_json(conn)
    if not data:
        return None
    client_ecdh_pub = load_pem_public_key(
        data['ecdh_pub'].encode(), backend=default_backend())

    if 'signature' in data and 'ecdsa_pub' in data:
        try:
            cli_ecdsa_pub = load_pem_public_key(
                data['ecdsa_pub'].encode(), backend=default_backend())
            cli_sig = bytes.fromhex(data['signature'])
            cli_ecdsa_pub.verify(
                cli_sig, data['ecdh_pub'].encode(), ECDSA(hashes.SHA256()))
            print(f"{label} Signature ECDSA client OK")
        except InvalidSignature:
            print(f"{label} ATTENTION : signature client invalide !")
            return None
    # Retourne la cle AES derivee
    secret = ecdh_priv.exchange(ECDH(), client_ecdh_pub)
    cle_aes = deriver_cle_aes(secret)
    return cle_aes
 # cote client


def _handshake_client(sock, ecdsa_priv=None, ecdsa_pub=None, label="") -> bytes:
    # Recoit {ecdh_pub, signature, ecdsa_pub} du serveur
    data = recevoir_json(sock)
    srv_ecdh_pub = load_pem_public_key(
        data['ecdh_pub'].encode(), backend=default_backend())
    # Verifie la signature ECDSA du serveur
    if 'signature' in data and 'ecdsa_pub' in data:
        try:
            srv_ecdsa_pub = load_pem_public_key(
                data['ecdsa_pub'].encode(), backend=default_backend())
            sig = bytes.fromhex(data['signature'])
            srv_ecdsa_pub.verify(
                sig, data['ecdh_pub'].encode(), ECDSA(hashes.SHA256()))
            print(f"{label} Signature ECDSA serveur OK")
        except InvalidSignature:
            print(f"{label} ATTENTION : signature serveur invalide !")
            sock.close()
            return None

    ecdh_priv = generate_private_key(SECP256R1(), default_backend())
    ecdh_pub = ecdh_priv.public_key()
    pub_bytes = ecdh_pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    payload = {'ecdh_pub': pub_bytes.decode()}

    if ecdsa_priv and ecdsa_pub:
        sig_cli = ecdsa_priv.sign(pub_bytes, ECDSA(hashes.SHA256()))
        ecdsa_pub_bytes = ecdsa_pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        payload['signature'] = sig_cli.hex()
        payload['ecdsa_pub'] = ecdsa_pub_bytes.decode()
    # Envoie sa propre cle ECDH (+ signature si ecdsa_priv fourni)
    envoyer_json(sock, payload)
    # Retourne la cle AES derivee
    secret = ecdh_priv.exchange(ECDH(), srv_ecdh_pub)
    cle_aes = deriver_cle_aes(secret)
    return cle_aes


# exo 6.1
#  Protocole : ECDH ephemere + ECDSA + AES-256-GCM
class ServeurTCPSecurise:

    def __init__(self, host: str = '127.0.0.1', port: int = 9999):
        self.host = host
        self.port = port
        self.ecdsa_priv = generate_private_key(SECP256R1(), default_backend())
        self.ecdsa_pub = self.ecdsa_priv.public_key()
        print(f"[TCP Serveur] Demarrage sur {host}:{port}")

    def _traiter_client(self, conn, addr):
        print(f"[TCP Serveur] Connexion de {addr}")
        try:
            cle_aes = _handshake_serveur(
                conn, self.ecdsa_priv, self.ecdsa_pub, "[TCP Serveur]")
            if not cle_aes:
                return
            print(
                f"[TCP Serveur] Handshake OK - Cle AES: {cle_aes.hex()[:16]}...")
            while True:
                paquet = recevoir_json(conn)
                if not paquet:
                    break
                iv = bytes.fromhex(paquet['iv'])
                ct = bytes.fromhex(paquet['ct'])
                tag = bytes.fromhex(paquet['tag'])
                msg = aes_gcm_dechiffrer(cle_aes, iv, ct, tag).decode('utf-8')
                print(f"[TCP Serveur <- client] {msg}")
                reponse = f"[ACK TCP] Message recu : '{msg}'"
                iv2, ct2, tag2 = aes_gcm_chiffrer(cle_aes, reponse.encode())
                envoyer_json(
                    conn, {'iv': iv2.hex(), 'ct': ct2.hex(), 'tag': tag2.hex()})
        except Exception as e:
            print(f"[TCP Serveur] Erreur : {e}")
        finally:
            conn.close()

    def demarrer(self, nb_connexions: int = 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(nb_connexions)
            s.settimeout(30)
            print(f"[TCP Serveur] En ecoute...")
            try:
                while True:
                    conn, addr = s.accept()
                    threading.Thread(target=self._traiter_client,
                                     args=(conn, addr), daemon=True).start()
            except socket.timeout:
                print("[TCP Serveur] Timeout - arret.")


class ClientTCPSecurise:
    # Client TCP securise : handshake ECDH + messages AES-256-GCM
    def __init__(self, host: str = '127.0.0.1', port: int = 9999):
        self.host = host
        self.port = port
        self.cle_aes = None
        self.sock = None

    def connecter(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self.cle_aes = _handshake_client(self.sock, label="[TCP Client]")
        print(
            f"[TCP Client] Handshake OK - Cle AES: {self.cle_aes.hex()[:16]}...")

    def envoyer(self, message: str):
        iv, ct, tag = aes_gcm_chiffrer(self.cle_aes, message.encode())
        envoyer_json(self.sock, {'iv': iv.hex(),
                     'ct': ct.hex(), 'tag': tag.hex()})
        paquet = recevoir_json(self.sock)
        iv2 = bytes.fromhex(paquet['iv'])
        ct2 = bytes.fromhex(paquet['ct'])
        tag2 = bytes.fromhex(paquet['tag'])
        reponse = aes_gcm_dechiffrer(self.cle_aes, iv2, ct2, tag2).decode()
        print(f"[TCP Client <- serveur] {reponse}")

    def deconnecter(self):
        if self.sock:
            self.sock.close()


BT_MODE = 'simulation'          # 'reel' ou 'simulation'
# Adresse MAC Bluetooth du serveur (mode reel)
MAC_SERVEUR = "00:1A:7D:DA:71:13"
CANAL_RFCOMM = 4                     # Canal RFCOMM 1-30
PORT_SIMUL = 9998                  # Port TCP pour la simulation


def _creer_socket_bt_serveur() -> socket.socket:

    # mode reel  : AF_BLUETOOTH + BTPROTO_RFCOMM, bind sur le canal RFCOMM
    # mode simul : socket TCP sur PORT_SIMUL (meme protocole applicatif)
    if BT_MODE == 'reel':
        sock = socket.socket(socket.AF_BLUETOOTH,
                             socket.SOCK_STREAM,
                             socket.BTPROTO_RFCOMM)
        sock.bind(("", CANAL_RFCOMM))   # "" = adresse MAC locale
        sock.listen(1)
        print(f"[BT Serveur] En ecoute sur canal RFCOMM {CANAL_RFCOMM}")
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('127.0.0.1', PORT_SIMUL))
        sock.listen(1)
        print(f"[BT Serveur] Simulation TCP sur 127.0.0.1:{PORT_SIMUL}")
    return sock


def _creer_socket_bt_client() -> socket.socket:
    # mode reel  : connexion Bluetooth vers MAC_SERVEUR sur CANAL_RFCOMM
    # mode simul : connexion TCP vers 127.0.0.1:PORT_SIMUL
    if BT_MODE == 'reel':
        sock = socket.socket(socket.AF_BLUETOOTH,
                             socket.SOCK_STREAM,
                             socket.BTPROTO_RFCOMM)
        sock.connect((MAC_SERVEUR, CANAL_RFCOMM))
        print(f"[BT Client] Connecte a {MAC_SERVEUR} canal {CANAL_RFCOMM}")
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('127.0.0.1', PORT_SIMUL))
        print(f"[BT Client] Connecte en simulation TCP 127.0.0.1:{PORT_SIMUL}")
    return sock


class ServeurBluetoothSecurise:

    def __init__(self):
        self.ecdsa_priv = generate_private_key(SECP256R1(), default_backend())
        self.ecdsa_pub = self.ecdsa_priv.public_key()
        mode = "reel (RFCOMM)" if BT_MODE == 'reel' else "simulation TCP"
        print(f"[BT Serveur] Mode : {mode}")
        print(f"[BT Serveur] Cle ECDSA P-256 generee.")

    def _traiter_client(self, conn, addr):
        print(f"[BT Serveur] Connexion de {addr}")
        try:
            cle_aes = _handshake_serveur(conn, self.ecdsa_priv,
                                         self.ecdsa_pub, "[BT Serveur]")
            if not cle_aes:
                print("[BT Serveur] Handshake echoue.")
                return
            print(
                f"[BT Serveur] Handshake OK - Cle AES: {cle_aes.hex()[:16]}...")
            while True:
                paquet = recevoir_json(conn)
                if not paquet:
                    break
                iv = bytes.fromhex(paquet['iv'])
                ct = bytes.fromhex(paquet['ct'])
                tag = bytes.fromhex(paquet['tag'])
                msg = aes_gcm_dechiffrer(cle_aes, iv, ct, tag).decode('utf-8')
                print(f"[BT Serveur <- client] {msg}")
                reponse = f"[ACK BT] Message recu : '{msg}'"
                iv2, ct2, tag2 = aes_gcm_chiffrer(cle_aes, reponse.encode())
                envoyer_json(
                    conn, {'iv': iv2.hex(), 'ct': ct2.hex(), 'tag': tag2.hex()})
        except Exception as e:
            print(f"[BT Serveur] Erreur : {e}")
        finally:
            conn.close()
            print("[BT Serveur] Connexion fermee.")

    def demarrer(self, timeout: int = 15):
        srv = _creer_socket_bt_serveur()
        srv.settimeout(timeout)
        try:
            conn, addr = srv.accept()
            t = threading.Thread(target=self._traiter_client,
                                 args=(conn, addr), daemon=True)
            t.start()
            t.join()
        except socket.timeout:
            print("[BT Serveur] Timeout - arret.")
        finally:
            srv.close()


class ClientBluetoothSecurise:

    def __init__(self):
        self.cle_aes = None
        self.sock = None
        self.ecdsa_priv = generate_private_key(SECP256R1(), default_backend())
        self.ecdsa_pub = self.ecdsa_priv.public_key()

    def connecter(self):
        self.sock = _creer_socket_bt_client()
        self.cle_aes = _handshake_client(self.sock,
                                         self.ecdsa_priv,
                                         self.ecdsa_pub,
                                         "[BT Client]")
        if self.cle_aes:
            print(
                f"[BT Client] Handshake OK - Cle AES: {self.cle_aes.hex()[:16]}...")

    def envoyer(self, message: str):
        iv, ct, tag = aes_gcm_chiffrer(self.cle_aes, message.encode())
        envoyer_json(self.sock, {'iv': iv.hex(),
                     'ct': ct.hex(), 'tag': tag.hex()})
        paquet = recevoir_json(self.sock)
        iv2 = bytes.fromhex(paquet['iv'])
        ct2 = bytes.fromhex(paquet['ct'])
        tag2 = bytes.fromhex(paquet['tag'])
        reponse = aes_gcm_dechiffrer(self.cle_aes, iv2, ct2, tag2).decode()
        print(f"[BT Client <- serveur] {reponse}")

    def deconnecter(self):
        if self.sock:
            self.sock.close()

# exo 6.3


class ChatUDPSecurise:

    def __init__(self, nom: str, port_local: int, port_distant: int,
                 host: str = '127.0.0.1', cle_aes: bytes = None):
        self.nom = nom
        self.host = host
        self.port_local = port_local
        self.port_distant = port_distant
        self.cle_aes = cle_aes or hashlib.sha256(b"cle_test_partagee").digest()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port_local))
        self.actif = True
        print(f"[{self.nom}] Chat UDP demarre sur port {port_local}")

    def _envoyer_msg(self, message: str):
        payload = json.dumps({
            'from': self.nom,
            'msg': message,
            'ts': time.time()
        }).encode()
        iv, ct, tag = aes_gcm_chiffrer(self.cle_aes, payload)
        paquet = json.dumps(
            {'iv': iv.hex(), 'ct': ct.hex(), 'tag': tag.hex()}).encode()
        self.sock.sendto(paquet, (self.host, self.port_distant))

    def _recevoir(self):
        while self.actif:
            try:
                self.sock.settimeout(1.0)
                data, _ = self.sock.recvfrom(65536)
                paquet = json.loads(data.decode())
                iv = bytes.fromhex(paquet['iv'])
                ct = bytes.fromhex(paquet['ct'])
                tag = bytes.fromhex(paquet['tag'])
                payload = aes_gcm_dechiffrer(self.cle_aes, iv, ct, tag)
                obj = json.loads(payload.decode())
                print(f"\n  [{obj['from']}] {obj['msg']}")
            except socket.timeout:
                continue
            except Exception:
                break

    def demarrer_reception(self):
        t = threading.Thread(target=self._recevoir, daemon=True)
        t.start()
        return t

    def arreter(self):
        self.actif = False
        self.sock.close()

# exo 6.4


class VoteElectronique:

    def __init__(self, bits: int = 256):
        from sympy import nextprime, primitive_root
        debut = 2 ** (bits - 1)
        self.p = nextprime(random.randint(debut, 2 * debut))
        self.g = int(primitive_root(self.p))
        self.x = random.randint(2, self.p - 2)
        self.y = pow(self.g, self.x, self.p)
        print(f"[Vote] Parametres ElGamal {bits} bits generes.")
        print(f"       Cle publique y = g^x mod p  (x reste secret)")

    def chiffrer_vote(self, vote: int) -> tuple:
        assert vote in (0, 1), "Le vote doit etre 0 (NON) ou 1 (OUI)."
        k = random.randint(2, self.p - 2)
        M = pow(self.g, vote, self.p)
        C1 = pow(self.g, k,    self.p)
        C2 = (M * pow(self.y, k, self.p)) % self.p
        return C1, C2

    def agreger_votes(self, votes_chiffres: list) -> tuple:
        C1_total = 1
        C2_total = 1
        for C1, C2 in votes_chiffres:
            C1_total = (C1_total * C1) % self.p
            C2_total = (C2_total * C2) % self.p
        return C1_total, C2_total

    def dechiffrer_total(self, C1_total: int, C2_total: int, nb_votants: int) -> int:
        s = pow(C1_total, self.x, self.p)
        s_inv = pow(s, self.p - 2, self.p)
        G_somme = (C2_total * s_inv) % self.p
        gi = 1
        for k in range(nb_votants + 1):
            if gi == G_somme:
                return k
            gi = (gi * self.g) % self.p
        return -1

    def simuler_election(self, votes: list):
        sep = "=" * 60
        print(f"\n{sep}")
        print("   EXERCICE 6.4 - Vote Electronique Homomorphe (ElGamal)")
        print(sep)
        print(f"  Nombre d'electeurs : {len(votes)}")
        print(f"  Votes reels (secret) : {votes}  <- invisibles au serveur\n")

        print("  Phase 1 : Chiffrement individuel des votes")
        votes_chiffres = []
        for i, v in enumerate(votes):
            c = self.chiffrer_vote(v)
            votes_chiffres.append(c)
            label = 'OUI' if v else 'NON'
            print(
                f"    Electeur {i+1:2d} : {label} -> C1={str(c[0])[:8]}..., C2={str(c[1])[:8]}...")

        print("\n  Phase 2 : Agregation homomorphe (serveur, sans cle privee)")
        C1_tot, C2_tot = self.agreger_votes(votes_chiffres)
        print(
            f"    Total chiffre : C1={str(C1_tot)[:10]}..., C2={str(C2_tot)[:10]}...")

        print("\n  Phase 3 : Depouillement (dechiffrement du total uniquement)")
        total_oui = self.dechiffrer_total(C1_tot, C2_tot, len(votes))
        total_non = len(votes) - total_oui
        attendu = sum(votes)

        print(f"\n  RESULTATS")
        print(f"  OUI : {total_oui:3d}  ({total_oui / len(votes) * 100:.0f}%)")
        print(f"  NON : {total_non:3d}  ({total_non / len(votes) * 100:.0f}%)")
        verdict = "OK" if total_oui == attendu else "ERREUR"
        print(f"  Verification (somme attendue = {attendu}) : {verdict}")

        print(f"\n  Garanties :")
        print(f"    [+] Confidentialite : votes individuels jamais dechiffres")
        print(
            f"    [+] Anonymat        : le serveur ne peut pas lier vote -> electeur")
        print(
            f"    [+] Integrite       : agregation homomorphe verifiable publiquement")
        print(
            f"    [+] Minimalite      : un seul dechiffrement (la somme totale)")
        print(sep)


def demo_tcp_securise():
    sep = "=" * 60
    print(f"\n{sep}")
    print("   EXERCICE 6.1 - TCP Securise (simulation memoire)")
    print("   ECDH P-256 + ECDSA + AES-256-GCM")
    print(sep)

    srv_priv = generate_private_key(SECP256R1(), default_backend())
    cli_priv = generate_private_key(SECP256R1(), default_backend())
    secret_srv = srv_priv.exchange(ECDH(), cli_priv.public_key())
    secret_cli = cli_priv.exchange(ECDH(), srv_priv.public_key())
    assert secret_srv == secret_cli

    cle_aes = deriver_cle_aes(secret_srv)
    print(f"\n  Handshake ECDH OK - Secret derive : {cle_aes.hex()}")

    messages = [
        "Bonjour Serveur ! Connexion securisee etablie.",
        "Donnees confidentielles : mot de passe = 1234.",
        "FIN"
    ]
    print(f"\n  {'Message':40s} | Chiffre (debut)  | Dechiffre")
    print(f"  {'-'*40}-+-{'-'*16}-+-{'-'*20}")
    for msg in messages:
        iv, ct, tag = aes_gcm_chiffrer(cle_aes, msg.encode())
        dec = aes_gcm_dechiffrer(cle_aes, iv, ct, tag).decode()
        print(f"  {msg[:40]:40s} | {ct.hex()[:16]} | {dec[:20]} OK")

    print(f"\n  [+] Confidentialite : AES-256-GCM")
    print(f"  [+] Integrite       : Tag GCM 128 bits")
    print(f"  [+] PFS             : cles ECDH ephemeres")
    print(sep)


def demo_bluetooth_securise():
    sep = "=" * 60
    print(f"\n{sep}")
    print("   EXERCICE 6.2 - Bluetooth RFCOMM Securise")
    print("   ECDH ephemere + ECDSA mutuelle + AES-256-GCM")
    if BT_MODE != 'reel':
        print(f"   Mode simulation : TCP 127.0.0.1:{PORT_SIMUL}")
        print(f"   (pour vrai BT : BT_MODE='reel' + renseigner MAC_SERVEUR)")
    print(sep)

    serveur = ServeurBluetoothSecurise()
    client = ClientBluetoothSecurise()
    erreurs = []

    def run_serveur():
        try:
            serveur.demarrer(timeout=15)
        except Exception as e:
            erreurs.append(str(e))

    t = threading.Thread(target=run_serveur, daemon=True)
    t.start()
    time.sleep(0.4)

    try:
        client.connecter()
        for msg in [
            "Appareil A -> B : canal Bluetooth chiffre.",
            "Transfert de donnees sensibles via RFCOMM.",
            "Fin de transmission."
        ]:
            client.envoyer(msg)
        client.deconnecter()
    except Exception as e:
        erreurs.append(str(e))

    t.join(timeout=8)

    if erreurs:
        for e in erreurs:
            print(f"  [ERREUR] {e}")
    else:
        print(f"\n  [+] Confidentialite     : AES-256-GCM sur RFCOMM")
        print(f"  [+] Auth. mutuelle      : ECDSA serveur ET client")
        print(f"  [+] Perfect Forward Sec.: cles ECDH ephemeres")
        print(f"  [+] Sans lib externe    : socket.AF_BLUETOOTH (Python 3.7+)")
    print(sep)


def demo_chat_udp():
    sep = "=" * 60
    print(f"\n{sep}")
    print("   EXERCICE 6.3 - Chat UDP Securise (simulation memoire)")
    print("   AES-256-GCM + cle pre-partagee")
    print(sep)

    cle = hashlib.sha256(b"secret_partage_alice_bob").digest()
    echanges = [
        ("Alice", "Salut Bob ! Canal securise operationnel."),
        ("Bob",   "Salut Alice ! Cle AES-256-GCM bien recue."),
        ("Alice", "Donnees sensibles transmises en securite."),
    ]
    for exp, msg in echanges:
        payload = json.dumps({'from': exp, 'msg': msg}).encode()
        iv, ct, tag = aes_gcm_chiffrer(cle, payload)
        dec = json.loads(aes_gcm_dechiffrer(cle, iv, ct, tag))
        print(f"\n  [{exp}] -> Chiffre  : {ct.hex()[:22]}...")
        print(f"  [{exp}] -> Dechiffre : [{dec['from']}] {dec['msg']}")
    print(sep)


if __name__ == "__main__":

    print("\nTP6 - EXERCICE 6.1 : TCP Securise ")
    demo_tcp_securise()

    print("\n TP6 - EXERCICE 6.2 : Bluetooth RFCOMM Securise ")
    demo_bluetooth_securise()

    print("\n TP6 - EXERCICE 6.3 : Chat UDP Securise ")
    demo_chat_udp()

    print("\nTP6 - EXERCICE 6.4 : Vote Electronique ")
    vote = VoteElectronique(bits=256)
    vote.simuler_election([1, 0, 1, 1, 0])
    votes_aleatoires = [random.randint(0, 1) for _ in range(10)]
    vote.simuler_election(votes_aleatoires)
