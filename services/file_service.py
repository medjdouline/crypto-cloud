"""
file_service.py  v2
--------------------
Logique métier : upload, download, suppression, partage de fichiers.

Améliorations v2 :
    - Validation magic bytes + taille via file_validator.py
    - Historique de téléchargements (table download_history)
"""

import os
import sys
import uuid

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from config import STORAGE_DIR, KEYS_DIR
from database.db import (
    add_file, get_file_by_id, get_files_by_user,
    delete_file as db_delete_file,
    add_log,
    share_file as db_share_file,
    get_files_shared_with_user,
    get_user_by_username,
    fetch_all, execute
)
from services.quota_service  import check_quota, add_to_quota, free_from_quota
from services.file_validator import validate_file

from services.crypto_service import (
    encrypt_file, decrypt_file, reencrypt_aes_key,
    sign_file, verify_signature, load_private_key_with_password, 
    load_public_key,                  
)
from database.db import get_user_by_id


# ── Chemins ───────────────────────────────────────────────────────────────────

def _get_user_storage_dir(user_id):
    path = os.path.join(STORAGE_DIR, f"user_{user_id}")
    os.makedirs(path, exist_ok=True)
    return path

def _get_user_keys_dir(user_id):
    return os.path.join(KEYS_DIR, f"user_{user_id}")

def _get_public_key_pem(user_id):
    path = os.path.join(_get_user_keys_dir(user_id), "public.pem")
    if not os.path.exists(path): return None
    with open(path, "r") as f: return f.read()

def _get_private_key_pem(user_id):
    path = os.path.join(_get_user_keys_dir(user_id), "private.pem")
    if not os.path.exists(path): return None
    with open(path, "r") as f: return f.read()



# ── Historique téléchargements ────────────────────────────────────────────────

def _init_download_history_table():
    """Crée la table download_history si elle n'existe pas."""
    execute("""
        CREATE TABLE IF NOT EXISTS download_history (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id       INTEGER NOT NULL,
            user_id       INTEGER NOT NULL,
            downloaded_at TEXT    NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

def _add_download_history(file_id, user_id):
    """Enregistre un téléchargement."""
    _init_download_history_table()
    execute(
        "INSERT INTO download_history (file_id, user_id) VALUES (?, ?)",
        (file_id, user_id)
    )

def get_download_history(file_id):
    """
    Retourne l'historique des téléchargements d'un fichier.
    [ { username, downloaded_at }, ... ]
    """
    _init_download_history_table()
    return fetch_all("""
        SELECT u.username, dh.downloaded_at
        FROM download_history dh
        JOIN users u ON dh.user_id = u.id
        WHERE dh.file_id = ?
        ORDER BY dh.downloaded_at DESC
    """, (file_id,))

def get_download_count(file_id):
    """Retourne le nombre total de téléchargements d'un fichier."""
    _init_download_history_table()
    rows = fetch_all(
        "SELECT COUNT(*) as cnt FROM download_history WHERE file_id = ?",
        (file_id,)
    )
    return rows[0]["cnt"] if rows else 0


# ── Upload ────────────────────────────────────────────────────────────────────
def upload_file(user_id, file_obj, password, ip=None):
    """
    Chiffre et stocke un fichier.
    """
    # 1. Récupérer les données du fichier
    original_name = file_obj.filename
    file_bytes = file_obj.read()  # ← ligne importante !
    file_size = len(file_bytes)

    # 2. Validation complète
    ok, message = validate_file(original_name, file_bytes)
    if not ok:
        return False, message

    # 3. Quota
    ok, message = check_quota(user_id, file_size)
    if not ok:
        return False, message

    # 4. Récupérer l'utilisateur depuis la BDD
    user = get_user_by_id(user_id)  # ← À créer dans database/db.py
    if not user:
        return False, "Utilisateur introuvable."

    # 5. Récupérer la clé publique (dans la BDD)
    public_key_pem = user["public_key"]
    if not public_key_pem:
        return False, "Clé publique introuvable."

    # 6. Chiffrement du fichier (crypto_service fait tout)
    crypto_result = encrypt_file(file_bytes, public_key_pem)
    
    # crypto_result contient :
    # - encrypted_file (bytes)
    # - encrypted_aes_key (base64)
    # - iv (base64)
    # - sha256_hash (string)

    # 7. Charger la clé privée pour signer
    try:
        private_key = load_private_key_with_password(user, password)
    except ValueError as e:
        return False, str(e)

    # 8. Signer le fichier ORIGINAL
    signature = sign_file(file_bytes, private_key)

    # 9. Sauvegarde disque du fichier chiffré
    stored_name = uuid.uuid4().hex + ".enc"
    storage_dir = _get_user_storage_dir(user_id)
    
    with open(os.path.join(storage_dir, stored_name), "wb") as f:
        f.write(crypto_result["encrypted_file"])
    
    # 10. Sauvegarde en BDD
    add_file(
        user_id,                           # owner_id
        original_name,                     # original_name
        stored_name,                       # stored_name
        file_size,                         # file_size
        crypto_result["sha256_hash"],      # sha256_hash
        signature,                         # signature
        crypto_result["encrypted_aes_key"],# encrypted_aes_key
        crypto_result["iv"]                # iv
    )
    
    # 11. Mettre à jour le quota et log
    add_to_quota(user_id, file_size)
    add_log(user_id, "upload", f"Uploadé : {original_name} ({file_size} octets)", ip)
    # Dans upload_file, après get_user_by_id(user_id)
    user = get_user_by_id(user_id)
    print("[DEBUG] User keys:", user.keys())  # ← Ajoutez cette ligne
    print("[DEBUG] User:", dict(user))        # ← Ajoutez cette ligne
    
    return True, "ok"


# ── Download ──────────────────────────────────────────────────────────────────
def download_file(user_id, file_id, password, ip=None):
    """
    Déchiffre et retourne le contenu d'un fichier.
    Vérifie l'intégrité SHA256 et la signature RSA.
    Enregistre dans l'historique.

    Retourne (True, bytes, nom) ou (False, message, "")
    """
    file = get_file_by_id(file_id)
    if not file:
        return False, "Fichier introuvable.", ""

    owner_id = file["owner_id"]

    # Vérification accès : propriétaire ou destinataire d'un partage
    if owner_id != user_id:
        # Récupérer les IDs des fichiers partagés avec l'utilisateur
        shared_files = get_files_shared_with_user(user_id)
        shared_ids = [sf["file_id"] for sf in shared_files]  # Note: c'est file_id, pas id
        if file_id not in shared_ids:
            return False, "Accès refusé.", ""

    # Récupérer l'utilisateur (propriétaire pour la clé privée)
    user = get_user_by_id(owner_id)
    if not user:
        return False, "Propriétaire introuvable.", ""

    # Charger la clé privée avec le mot de passe
    try:
        private_key = load_private_key_with_password(user, password)
    except ValueError as e:
        return False, str(e), ""

    # Lire le fichier chiffré (plus de fichier .key séparé !)
    storage_dir = _get_user_storage_dir(owner_id)
    enc_path = os.path.join(storage_dir, file["stored_name"])
    
    if not os.path.exists(enc_path):
        return False, "Fichier introuvable sur le disque.", ""

    with open(enc_path, "rb") as f:
        encrypted_bytes = f.read()

    # Préparer le file_record pour decrypt_file (les données sont en BDD)
    file_record = {
        "encrypted_aes_key": file["encrypted_aes_key"],
        "iv": file["iv"],
        "sha256_hash": file["sha256_hash"]
    }

    # Déchiffrer (vérifie l'intégrité automatiquement)
    try:
        original_bytes = decrypt_file(encrypted_bytes, file_record, private_key)
    except ValueError as e:
        return False, str(e), ""

    # Vérifier la signature
    public_key = load_public_key(user)
    if not verify_signature(original_bytes, file["signature"], public_key):
        return False, "Signature invalide : authenticité non vérifiée !", ""

    # Historique + log
    _add_download_history(file_id, user_id)
    add_log(user_id, "download", f"Téléchargé : {file['original_name']}", ip)

    return True, original_bytes, file["original_name"]


# ── Suppression ───────────────────────────────────────────────────────────────
def delete_file(user_id, file_id, ip=None):
    """Supprime un fichier du disque + DB + libère le quota."""
    file = get_file_by_id(file_id)
    if not file:
        return False, "Fichier introuvable."
    if file["owner_id"] != user_id:
        return False, "Vous ne pouvez supprimer que vos propres fichiers."

    storage_dir = _get_user_storage_dir(user_id)
    enc_path = os.path.join(storage_dir, file["stored_name"])
    # Supprimer UNIQUEMENT le fichier .enc (plus de .key)
    
    if os.path.exists(enc_path):
        os.remove(enc_path)

    db_delete_file(file_id)
    free_from_quota(user_id, file["file_size"])
    add_log(user_id, "delete", f"Supprimé : {file['original_name']}", ip)

    return True, "ok"



# ── Partage ───────────────────────────────────────────────────────────────────

def share_file(owner_id, file_id, recipient_username, owner_password, ip=None):
    """Partage un fichier avec un autre utilisateur."""
    
    # 1. Vérifications
    file = get_file_by_id(file_id)
    if not file:
        return False, "Fichier introuvable."
    if file["owner_id"] != owner_id:
        return False, "Vous ne pouvez partager que vos propres fichiers."

    recipient = get_user_by_username(recipient_username)
    if not recipient:
        return False, f"Utilisateur '{recipient_username}' introuvable."
    if recipient["id"] == owner_id:
        return False, "Vous ne pouvez pas partager un fichier avec vous-même."

    # 2. Vérifier si déjà partagé (utilise fetch_one)
    from database.db import fetch_one
    existing = fetch_one(
        "SELECT id FROM shared_files WHERE file_id = ? AND shared_with = ?",
        (file_id, recipient["id"])
    )
    if existing:
        return False, f"Ce fichier est déjà partagé avec '{recipient_username}'."

    # 3. Récupérer le propriétaire et sa clé privée
    owner = get_user_by_id(owner_id)
    if not owner:
        return False, "Propriétaire introuvable."

    try:
        owner_private_key = load_private_key_with_password(owner, owner_password)
    except ValueError as e:
        return False, str(e)

    # 4. Récupérer la clé publique du destinataire
    recipient_public_key_pem = recipient["public_key"]
    if not recipient_public_key_pem:
        return False, f"Clé publique de '{recipient_username}' introuvable."

    # 5. Rechiffrer la clé AES pour le destinataire
    try:
        encrypted_for_recipient = reencrypt_aes_key(
            file,                     # file_record
            owner_private_key,        # objet clé privée
            recipient_public_key_pem  # clé publique du destinataire
        )
    except Exception as e:
        return False, f"Erreur lors du rechiffrement: {str(e)}"

    # 6. Créer le partage en BDD avec la clé (utilise execute directement)
    from database.db import execute
    try:
        share_id = execute(
            """INSERT INTO shared_files 
               (file_id, shared_by, shared_with, encrypted_aes_key_for_recipient) 
               VALUES (?, ?, ?, ?)""",
            (file_id, owner_id, recipient["id"], encrypted_for_recipient)
        )
        
        if not share_id:
            return False, "Erreur lors de l'enregistrement du partage."
            
    except Exception as e:
        print(f"[ERROR] share_file: {e}")
        return False, f"Erreur base de données: {e}"

    # 7. Log
    add_log(owner_id, "share", f"'{file['original_name']}' → {recipient_username}", ip)
    
    return True, "ok"


# ── Listes ────────────────────────────────────────────────────────────────────

def list_user_files(user_id):
    """Retourne les fichiers de l'utilisateur + compteur de téléchargements."""
    files = get_files_by_user(user_id)
    result = []
    for f in files:
        d = dict(f)
        d["download_count"] = get_download_count(f["id"])
        result.append(d)
    return result

def list_shared_with_me(user_id):
    """Retourne les fichiers partagés avec l'utilisateur."""
    return get_files_shared_with_user(user_id)

