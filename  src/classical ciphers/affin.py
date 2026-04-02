import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_base import AlgorithmeCryptographique

class Affine (AlgorithmeCryptographique):
  taille_alphabet = 26

  def __init__(self):
    self.valeurs_a_valides = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]


  #calcule de pgcd 
  def _pgcd(self , x , y):
    while y : 
      x , y = y , x % y 
    return x
  
  # verifier la cle 
  def _valider_cle (self , cle):

    # make sure it's a tuple of 2 elemnets a & b:
    if not isinstance(cle , tuple) or len(cle) != 2:
      raise ValueError ("la cle doit etre un tuple (a , b )")
    a , b = cle 

    # make sure a & b are integeres 
    if not isinstance(a, int) or not isinstance(b, int):
      raise ValueError("les valeurs a et b doivent etre des entiers.")
    
    #make sure pgcd (a , 26) =1 
    if self._pgcd(a, self.taille_alphabet) != 1:
      raise ValueError(f"'a={a}' invalide ! 'a' doit etre premier avec 26.\n"
      f"valeurs valides : {self.valeurs_a_valides}")
    
    # make sure 0 < b < 25
    if not (0 <= b < self.taille_alphabet):
      raise ValueError(f"'b={b}' invalide ! 'b' doit etre entre 0 et 25.")
    

  def chiffrer(self, texte_clair, cle):
    self._valider_cle(cle)
    a, b = cle
    resultat = []

    for caractere in texte_clair :
      if caractere.isalpha():
        # 1.convertir en majuscule et avoir la pos
        x = ord(caractere.upper()) - ord("A")

        #2. appliquer la formule de chiffrement de Affine 
        x_chiffre = (a * x + b ) % self.taille_alphabet

        #3. conserver la casse originale
        lettre_chiffree = chr(x_chiffre + ord('A'))
        if caractere.islower():
          lettre_chiffree = lettre_chiffree.lower()

        resultat.append(lettre_chiffree)
      else:
         resultat.append(caractere)

    return ''.join(resultat)
  

  #calculer l'inverse multiplicatif
  def _inverse_multiplicatif (self  , a, m):
    for i in range (1 , m):
      if (a * i ) % m == 1 :
        return i 
    raise ValueError(f"pas d'inverse multiplicatif pour a={a} mod {m}")
  

  def dechiffrer(self, texte_chiffre, cle):
    self._valider_cle(cle)
    a , b = cle 
    a_inv = self._inverse_multiplicatif(a , self.taille_alphabet)
    resultat = []

    for caractere in texte_chiffre:
      if caractere.isalpha():
        # 1.convertir en majuscule et avoir la pos
        y = ord(caractere.upper()) - ord("A")

        ##2. appliquer la formule de dechiffrement de Affine 
        x_dechiffre = (a_inv * (y - b)) % self.taille_alphabet

        #3.conserver la casse originale
        lettre_dechiffree = chr(x_dechiffre + ord('A'))
        if caractere.islower():
          lettre_dechiffree = lettre_dechiffree.lower()

        resultat.append(lettre_dechiffree)

      else:
        resultat.append(caractere)
      
    return ''.join(resultat)




if __name__ == "__main__":
    affine = Affine()
    cle = (7, 3)

    texte_original  = "Hello World!"
    texte_chiffre   = affine.chiffrer(texte_original, cle)
    texte_dechiffre = affine.dechiffrer(texte_chiffre, cle)

    print(f"original   : {texte_original}")
    print(f"chiffré    : {texte_chiffre}")
    print(f"dechiffré  : {texte_dechiffre}")


