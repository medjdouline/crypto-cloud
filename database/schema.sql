-- ── users ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    username              TEXT    NOT NULL UNIQUE,
    email                 TEXT    NOT NULL UNIQUE,
    password_hash         TEXT    NOT NULL,
    role                  TEXT    NOT NULL DEFAULT 'user'
                                  CHECK (role IN ('user', 'admin')),
    is_active             INTEGER NOT NULL DEFAULT 1,
    created_at            TEXT    NOT NULL DEFAULT (datetime('now')),

    -- Clé publique RSA (partageable, pas besoin de chiffrer)
    public_key            TEXT    NOT NULL DEFAULT '',

    -- Chose 1 : clé privée RSA chiffrée avec le mot de passe
    private_key_encrypted TEXT    NOT NULL DEFAULT '',
    private_key_salt      TEXT    NOT NULL DEFAULT '',  -- sel1 pour PBKDF2(mdp)

    -- Chose 2 : clé privée RSA chiffrée avec les 12 mots
    recovery_key_encrypted TEXT   NOT NULL DEFAULT '',
    recovery_salt          TEXT   NOT NULL DEFAULT '',  -- sel2 pour PBKDF2(12 mots)

    -- Chose 3 : hash des 12 mots pour vérification
    recovery_phrase_hash   TEXT   NOT NULL DEFAULT '',  -- PBKDF2(12 mots + sel3)
    recovery_phrase_salt   TEXT   NOT NULL DEFAULT ''   -- sel3
    -- ↑ pas de virgule sur la dernière ligne !
);

-- ── quotas ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS quotas (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL UNIQUE,
    quota_max  INTEGER NOT NULL DEFAULT 104857600
                       CHECK (quota_max > 0),
    quota_used INTEGER NOT NULL DEFAULT 0
                       CHECK (quota_used >= 0),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ── files ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS files (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id          INTEGER NOT NULL,
    original_name     TEXT    NOT NULL,
    stored_name       TEXT    NOT NULL UNIQUE,
    file_size         INTEGER NOT NULL CHECK (file_size > 0),
    sha256_hash       TEXT    NOT NULL,   -- hash du fichier ORIGINAL pour intégrité
    signature         TEXT    NOT NULL,   -- signature RSA en base64
    encrypted_aes_key TEXT    NOT NULL,   -- clé AES chiffrée par RSA public de l'owner
    iv                TEXT    NOT NULL,   -- IV utilisé pour chiffrer le fichier avec AES
    uploaded_at       TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ── shared_files ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS shared_files (
    id                              INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id                         INTEGER NOT NULL,
    shared_by                       INTEGER NOT NULL,
    shared_with                     INTEGER NOT NULL,
    encrypted_aes_key_for_recipient TEXT    NOT NULL,  -- clé AES rechiffrée avec RSA public du destinataire
    shared_at                       TEXT    NOT NULL DEFAULT (datetime('now')),
    CHECK (shared_by != shared_with),
    UNIQUE (file_id, shared_with),
    FOREIGN KEY (file_id)     REFERENCES files(id) ON DELETE CASCADE,
    FOREIGN KEY (shared_by)   REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (shared_with) REFERENCES users(id) ON DELETE CASCADE
);

-- ── logs ──────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS logs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER,
    action    TEXT NOT NULL
              CHECK (action IN (
                  'login', 'logout', 'upload', 'download',
                  'delete', 'share', 'register', 'password_change',
                  'crypto_keygen', 'crypto_encrypt', 'crypto_decrypt', 'crypto_share'
              )),
    details   TEXT,
    ip        TEXT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Mettre à jour la contrainte CHECK
ALTER TABLE logs RENAME TO logs_old;
CREATE TABLE logs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER,
    action    TEXT NOT NULL
              CHECK (action IN (
                  'login', 'logout', 'upload', 'download','update',
                  'delete', 'share', 'register', 'password_change',
                  'crypto_keygen', 'crypto_encrypt', 'crypto_decrypt', 
                  'crypto_sign', 'crypto_verify', 'crypto_share', 
                  'crypto_load_private'
              )),
    details   TEXT,
    ip        TEXT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
INSERT INTO logs SELECT * FROM logs_old;
DROP TABLE logs_old;
