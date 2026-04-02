import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_base import AlgorithmeCryptographique

class RC4(AlgorithmeCryptographique):

  def _valider_cle(self, cle):
    if not isinstance(cle, str):
      raise ValueError("La cle doit etre une chaine de caracteres.")
    if not (1 <= len(cle) <= 256):
      raise ValueError("La cle doit contenir entre 1 et 256 caracteres.")
    
  def _ksa(self, cle):
      cle_octets = [ord(c) for c in cle]
      longueur_cle = len(cle_octets)
      S = list(range(256))
      j = 0
      for i in range(256):
        j = (j + S[i] + cle_octets[i % longueur_cle]) % 256
        S[i], S[j] = S[j], S[i]
      return S
  
  def _prga(self, S, longueur):
    S = S.copy()
    i = 0
    j = 0
    keystream = []
    for _ in range(longueur):
      i = (i + 1) % 256
      j = (j + S[i]) % 256
      S[i], S[j] = S[j], S[i]
      k = S[(S[i] + S[j]) % 256]
      keystream.append(k)
    return keystream
  
  def _xor(self, texte_octets, keystream):
    return [t ^ k for t, k in zip(texte_octets, keystream)]
  
  def chiffrer(self, texte_clair, cle):
   
   # convert text to bytes
   texte_octets = [ord(c) for c in texte_clair]

   # generate keystream
   S = self._ksa(cle)
   keystream = self._prga(S, len(texte_octets))

   # XOR text with keystream
   chiffre_octets = self._xor(texte_octets, keystream)

   # return as hexadecimal string
   return ''.join(f'{octet:02x}' for octet in chiffre_octets)
  
  def dechiffrer(self, texte_chiffre, cle):
   self._valider_cle(cle)

   # convert hex string back to bytes
   chiffre_octets = [int(texte_chiffre[i:i+2], 16) for i in range(0, len(texte_chiffre), 2)]

   # generate same keystream
   S = self._ksa(cle)
   keystream = self._prga(S, len(chiffre_octets))

   # XOR again to decrypt
   dechiffre_octets = self._xor(chiffre_octets, keystream)

   # convert bytes back to text
   return ''.join(chr(octet) for octet in dechiffre_octets)


if __name__ == "__main__":
    rc4 = RC4()
    cle = "SECRET"

    texte_original = "Hello World!"
    texte_chiffre  = rc4.chiffrer(texte_original, cle)
    texte_dechiffre = rc4.dechiffrer(texte_chiffre, cle)

    print(f"Original   : {texte_original}")
    print(f"Chiffré    : {texte_chiffre}")
    print(f"Déchiffré  : {texte_dechiffre}")