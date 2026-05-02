from abc import ABC, abstractmethod

class AlgorithmeCryptographique(ABC):
    """
    Classe abstraite de base pour tous les algorithmes de cryptographie.
    Chaque algorithme (César, AES, DES, etc.) devra hériter de cette classe
    et implémenter obligatoirement ces deux méthodes.
    """

    @abstractmethod
    def chiffrer(self, texte_clair, cle):
        """
        Chiffre un message en clair avec une clé donnée.
        """
        pass

    @abstractmethod
    def dechiffrer(self, texte_chiffre, cle):
        """
        Déchiffre un message chiffré avec une clé donnée.
        """