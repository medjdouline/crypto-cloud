# fix_logs.py
import sqlite3
from config import DB_PATH

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Recréer la table logs avec les nouvelles actions
cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs_new (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id   INTEGER,
        action    TEXT NOT NULL
                  CHECK (action IN (
                      'login', 'logout', 'upload', 'download',
                      'delete', 'share', 'register', 'password_change',
                      'password_reset', 'crypto_keygen', 'crypto_encrypt', 
                      'crypto_decrypt', 'crypto_sign', 'crypto_verify', 
                      'crypto_share', 'crypto_load_private'
                  )),
        details   TEXT,
        ip        TEXT,
        timestamp TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    )
""")

# Copier les données
cursor.execute("INSERT INTO logs_new (id, user_id, action, details, ip, timestamp) SELECT * FROM logs")

# Supprimer l'ancienne table
cursor.execute("DROP TABLE logs")

# Renommer la nouvelle table
cursor.execute("ALTER TABLE logs_new RENAME TO logs")

conn.commit()
conn.close()

print("Table logs mise à jour avec password_reset")