import sqlite3
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from config import DB_PATH, STORAGE_DIR, KEYS_DIR


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    os.makedirs(STORAGE_DIR, exist_ok=True)
    os.makedirs(KEYS_DIR, exist_ok=True)
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, "r") as f:
        schema = f.read()
    with get_connection() as conn:
        conn.executescript(schema)
        conn.commit()
    print("[DB] Base de données initialisée.")


def fetch_one(query, params=()):
    with get_connection() as conn:
        return conn.execute(query, params).fetchone()

def fetch_all(query, params=()):
    with get_connection() as conn:
        return conn.execute(query, params).fetchall()

def execute(query, params=()):
    with get_connection() as conn:
        cursor = conn.execute(query, params)
        conn.commit()
        return cursor.lastrowid


# ── Users ─────────────────────────────────────────────────────────────────────
def get_user_by_username(username):
    return fetch_one("SELECT * FROM users WHERE username = ?", (username,))

def get_user_by_id(user_id):
    return fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))

def get_all_users():
    return fetch_all("SELECT id, username, email, role, is_active, created_at FROM users")

def create_user(username, email, password_hash, role="user", 
                public_key="", private_key_encrypted="", private_key_salt="",
                recovery_key_encrypted="", recovery_salt=""):
    """Crée un nouvel utilisateur avec toutes ses clés."""
    user_id = execute(
        """INSERT INTO users 
           (username, email, password_hash, role, 
            public_key, private_key_encrypted, private_key_salt,
            recovery_key_encrypted, recovery_salt) 
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (username, email, password_hash, role, 
         public_key, private_key_encrypted, private_key_salt,
         recovery_key_encrypted, recovery_salt)
    )
    execute("INSERT INTO quotas (user_id) VALUES (?)", (user_id,))
    return user_id

def set_user_active(user_id, active):
    execute("UPDATE users SET is_active = ? WHERE id = ?", (1 if active else 0, user_id))

def delete_user(user_id):
    execute("DELETE FROM users WHERE id = ?", (user_id,))


# ── Quotas ────────────────────────────────────────────────────────────────────
def get_quota(user_id):
    return fetch_one("SELECT * FROM quotas WHERE user_id = ?", (user_id,))

def update_quota_used(user_id, delta):
    """Met à jour l'espace utilisé. Retourne True si succès."""
    quota = get_quota(user_id)
    if quota is None:
        print(f"[ERROR] Quota non trouvé pour user_id={user_id}")
        return False
    
    new_used = max(0, quota["quota_used"] + delta)
    if new_used > quota["quota_max"]:
        print(f"[ERROR] Quota dépassé: {new_used} > {quota['quota_max']}")
        return False
    
    execute("UPDATE quotas SET quota_used = ? WHERE user_id = ?", (new_used, user_id))
    return True

def set_quota_max(user_id, new_max):
    execute("UPDATE quotas SET quota_max = ? WHERE user_id = ?", (new_max, user_id))

def debug_quota(user_id):
    """Fonction de debug pour voir le quota."""
    quota = get_quota(user_id)
    if quota:
        return dict(quota)
    return None

# ── Files ─────────────────────────────────────────────────────────────────────
def add_file(owner_id, original_name, stored_name, file_size, sha256_hash, signature, encrypted_aes_key, iv):
    """Ajoute un fichier avec les informations cryptographiques complètes."""
    return execute(
        """INSERT INTO files 
           (owner_id, original_name, stored_name, file_size, sha256_hash, signature, encrypted_aes_key, iv) 
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (owner_id, original_name, stored_name, file_size, sha256_hash, signature, encrypted_aes_key, iv)
    )

def get_files_by_user(user_id):
    return fetch_all("SELECT * FROM files WHERE owner_id = ? ORDER BY uploaded_at DESC", (user_id,))

def get_file_by_id(file_id):
    return fetch_one("SELECT * FROM files WHERE id = ?", (file_id,))

def delete_file(file_id):
    execute("DELETE FROM files WHERE id = ?", (file_id,))


# ── Partages ──────────────────────────────────────────────────────────────────
def share_file(file_id, shared_by, shared_with):
    """Partage un fichier. Retourne l'ID du partage ou None si déjà partagé."""
    try:
        # Vérifier d'abord si le partage existe déjà
        existing = fetch_one(
            "SELECT id FROM shared_files WHERE file_id = ? AND shared_with = ?",
            (file_id, shared_with)
        )
        if existing:
            return None  # Déjà partagé
        
        # Créer le partage
        return execute(
            "INSERT INTO shared_files (file_id, shared_by, shared_with) VALUES (?, ?, ?)",
            (file_id, shared_by, shared_with)
        )
    except Exception as e:
        print(f"[ERROR] share_file: {e}")
        return None
    
def get_files_shared_with_user(user_id):
    return fetch_all("""
        SELECT f.*, u.username AS owner_name, sf.shared_at
        FROM shared_files sf
        JOIN files f ON sf.file_id = f.id
        JOIN users u ON f.owner_id = u.id
        WHERE sf.shared_with = ?
        ORDER BY sf.shared_at DESC
    """, (user_id,))


# ── Logs ──────────────────────────────────────────────────────────────────────
def add_log(user_id, action, details=None, ip=None):
    execute(
        "INSERT INTO logs (user_id, action, details, ip) VALUES (?, ?, ?, ?)",
        (user_id, action, details, ip)
    )

def get_logs_by_user(user_id):
    return fetch_all(
        "SELECT * FROM logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 50",
        (user_id,)
    )

def get_all_logs():
    return fetch_all("""
        SELECT l.*, u.username
        FROM logs l
        LEFT JOIN users u ON l.user_id = u.id
        ORDER BY l.timestamp DESC
        LIMIT 200
    """)
