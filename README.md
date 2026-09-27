# CryptoCloud

Système de stockage cloud sécurisé utilisant un chiffrement hybride RSA + AES.

## Fonctionnalités
- Chiffrement hybride des fichiers (RSA pour l'échange de clé, AES pour les données)
- Gestion des clés (keys/)
- Stockage sécurisé des fichiers (storage/)
- API/routes pour l'upload et le téléchargement (routes/, services/)
- Interface web (templates/, static/)

## Installation
```bash
pip install -r requirements.txt
python main.py
```

## Technologies
- Langage : Python (Flask)
- Cryptographie : RSA + AES (chiffrement hybride)
