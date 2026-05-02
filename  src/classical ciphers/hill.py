import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_base import AlgorithmeCryptographique

class Hill(AlgorithmeCryptographique):
  taill_alphabet = 26

  #calcule de pgcd 
  def _pgcd(self , x , y):
    while y : 
      x , y = y , x % y 
    return x
  
  #calculer l'inverse multiplicatif
  def _inverse_multiplicatif (self  , a, m):
    for i in range (1 , m):
      if (a * i ) % m == 1 :
        return i 
    raise ValueError(f"pas d'inverse multiplicatif pour a={a} mod {m}")
  
   # verifier la cle 
  def _valider_cle (self , cle):
    # make sure it's a list of 4 elemnets a  b  c  d :
    if not isinstance(cle , list) or len(cle) != 4:
      raise ValueError ("la cle doit etre les valeurs une liste de 4 entiers [a, b, c, d]")
    
    # make sure a & b are integeres 
    if not all(isinstance(x, int) for x in cle):
      raise ValueError("tout les elements de la cle doivent etre des entiers")
    
    #make sure pgcd (det , 26) =1 
    a , b , c , d  = cle 
    det = (a * d - b * c) % self.taill_alphabet
    if det == 0 or self._pgcd(det , self.taill_alphabet) != 1:
      raise ValueError(f"Matrice invalide ! det={det} n'est pas inversible mod 26.\n"
                f"Le déterminant doit être premier avec 26.")
    
    # make sure 0 < b < 25
    if not (0 <= b < self.taill_alphabet):
      raise ValueError(f"'b={b}' invalide ! 'b' doit etre entre 0 et 25.")
    
  # construire la matrice 
  def _construire_mat ( slef , cle):
    a , b ,c ,d = cle 
    return [[a , b] , [c ,d ]]
  
  #inverse de la matrice 
  def _inverse_mat(self , cle):
    a , b ,c ,d = cle 
    det = (a * d - b * c) % self.taill_alphabet
    det_inv = self._inverse_multiplicatif(det , self.taill_alphabet)

    # inverse matrix mod 26
    return [[(det_inv *  d) % self.taill_alphabet, (det_inv * -b) % self.taill_alphabet],[(det_inv * -c) % self.taill_alphabet, (det_inv *  a) % self.taill_alphabet]]
  
  def _multiplier_matrice_vecteur(self, matrice, vecteur):
    return [(matrice[0][0] * vecteur[0] + matrice[0][1] * vecteur[1]) % self.taill_alphabet,(matrice[1][0] * vecteur[0] + matrice[1][1] * vecteur[1]) % self.taill_alphabet]
  
  # garde uniquement les lettres et met en majuscule & si le nombre de lettres est impair  ajoute 'X' à la fin.
  def _preparer_texte(self, texte):
    lettres = [c.upper() for c in texte if c.isalpha()]
    if len(lettres) % 2 != 0:
      lettres.append('X')  # padding
    return lettres
  
  def chiffrer(self, texte_clair, cle):
    self._valider_cle(cle)
    matrice = self._construire_mat(cle)
    lettres = self._preparer_texte(texte_clair)
    resultat = []

    #process 2 letters at a time 
    for i in range(0 , len(lettres) , 2):
      #convert letters to numbers 
      vecteur = [ord(lettres[i]) - ord('A') , ord(lettres[i+1]) - ord('A')]

      # multiply matrix by vector
      chiffre = self._multiplier_matrice_vecteur(matrice, vecteur)

      # convert back to letters
      resultat.append(chr(chiffre[0] + ord('A')))
      resultat.append(chr(chiffre[1] + ord('A')))

    return ''.join(resultat)
  
  def dechiffrer(self, texte_chiffre, cle):
    self._valider_cle(cle)
    mat_inv = self._inverse_mat(cle)
    lettres = self._preparer_texte(texte_chiffre)
    resultat = []

    for i in range(0, len(lettres), 2):
      vecteur = [ord(lettres[i]) - ord('A'),ord(lettres[i + 1]) - ord('A')]

      dechiffre = self._multiplier_matrice_vecteur(mat_inv, vecteur)

      resultat.append(chr(dechiffre[0] + ord('A')))
      resultat.append(chr(dechiffre[1] + ord('A')))

    return ''.join(resultat)

if __name__ == "__main__":
    hill = Hill()
    cle = [3, 2, 7, 5] 

    texte_original  = "HELLO"
    texte_chiffre   = hill.chiffrer(texte_original, cle)
    texte_dechiffre = hill.dechiffrer(texte_chiffre, cle)

    print(f"Original   : {texte_original}")
    print(f"Chiffré    : {texte_chiffre}")
    print(f"Déchiffré  : {texte_dechiffre}")
