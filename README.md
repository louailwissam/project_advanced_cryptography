# 🔐 Projet de Cryptographie Avancée

Bienvenue dans le dépôt du projet de **Cryptographie Avancée**. 
Ce projet a pour but de rassembler et d'implémenter en Python les principaux algorithmes de cryptographie étudiés en cours, en allant des méthodes historiques aux standards modernes de chiffrement symétrique.

## 🚀 Fonctionnalités et Algorithmes (en cours)

Le projet est conçu autour d'une architecture Orientée Objet (Design Pattern Stratégie) permettant d'ajouter et d'utiliser facilement différents algorithmes via une interface commune.

### 🏛️ Cryptographie Classique (Historique)
- [ ] Chiffre de César
- [ ] Chiffre Affine
- [ ] Chiffre de Vigenère
- [ ] Chiffre de Playfair
- [ ] Chiffre de Hill
- [ ] Masque Jetable (One Time Pad)

### 💻 Cryptographie Moderne (Symétrique)
- [ ] **Chiffrement par flux :** RC4
- [ ] **Chiffrement par blocs :** DES (Data Encryption Standard)
- [ ] **Chiffrement par blocs :** AES (Advanced Encryption Standard)

### ⚙️ Modes de fonctionnement
- [ ] ECB (Electronic Code Book)
- [ ] CBC (Cipher Block Chaining)

## 📂 Architecture du projet

Le code source est organisé de manière modulaire :

```text
project_advanced_cryptography/
├── src/
│   ├── crypto_base.py      # Classe abstraite définissant l'interface (chiffrer/dechiffrer)
│   ├── classiques/         # Implémentation des algorithmes historiques
│   ├── modernes/           # Implémentation des algorithmes symétriques (DES, AES...)
│   └── modes/              # Implémentation des modes opératoires (CBC, ECB...)
├── main.py                 # Point d'entrée du programme (Menu utilisateur CLI)
└── README.md               # Documentation du projet
