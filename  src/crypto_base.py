from abc import ABC, abstractmethod

class AlgorithmeCryptographique(ABC):
    """Classe abstraite de base pour tous les algorithmes."""
    
    @abstractmethod
    def chiffrer(self, texte_clair, cle):
        pass

    @abstractmethod
    def dechiffrer(self, texte_chiffre, cle):
        pass