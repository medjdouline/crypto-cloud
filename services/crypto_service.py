import os
import base64
import hashlib
import json
import inspect
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ─────────────────────────────────────────────────────────────────────────────
#  FONCTION DE LOG CRYPTOGRAPHIQUE
# ─────────────────────────────────────────────────────────────────────────────

def _log_crypto_action(user_id, action, details, level="INFO"):
    """Ajoute un log crypto avec le contexte de la fonction appelante."""
    try:
        caller_frame = inspect.currentframe().f_back
        caller_name = caller_frame.f_code.co_name if caller_frame else "unknown"
        full_details = f"[{caller_name}] {details}"
        
        from database.db import add_log
        add_log(user_id, action, full_details, None)
    except Exception as e:
        print(f"[LOG ERROR] Failed to add crypto log: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTES
# ─────────────────────────────────────────────────────────────────────────────

PBKDF2_ITERATIONS = 100_000
AES_KEY_SIZE = 32
RSA_KEY_SIZE = 2048
RECOVERY_WORDS_FILE = os.path.join(os.path.dirname(__file__), "wordlist.txt")


# ─────────────────────────────────────────────────────────────────────────────
#  1. DÉRIVATION DE CLÉ (PBKDF2)
# ─────────────────────────────────────────────────────────────────────────────

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
#  2. CHIFFREMENT / DÉCHIFFREMENT AES
# ─────────────────────────────────────────────────────────────────────────────

def aes_encrypt(data: bytes, key: bytes) -> tuple[bytes, bytes]:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(data) + encryptor.finalize()
    return iv, encrypted


def aes_decrypt(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()


# ─────────────────────────────────────────────────────────────────────────────
#  3. PHRASE DE RÉCUPÉRATION
# ─────────────────────────────────────────────────────────────────────────────

def generate_recovery_phrase() -> str:
    if os.path.exists(RECOVERY_WORDS_FILE):
        with open(RECOVERY_WORDS_FILE, "r", encoding="utf-8") as f:
            words = [line.strip() for line in f if line.strip()]
        chosen = []
        for _ in range(12):
            index = int.from_bytes(os.urandom(4), "big") % len(words)
            chosen.append(words[index])
        return " ".join(chosen)
    else:
        return " ".join(os.urandom(4).hex() for _ in range(12))


def phrase_to_key_and_salt(phrase: str) -> tuple[bytes, bytes]:
    salt = os.urandom(16)
    key = derive_key_from_password(phrase, salt)
    return key, salt


# ─────────────────────────────────────────────────────────────────────────────
#  4. GÉNÉRATION DE LA PAIRE RSA
# ─────────────────────────────────────────────────────────────────────────────

def generate_rsa_keys(password: str, user_id=None) -> dict:
    start_time = time.time()
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
    )
    public_key = private_key.public_key()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    salt_password = os.urandom(16)
    aes_key_password = derive_key_from_password(password, salt_password)
    iv_password, encrypted_private_key_password = aes_encrypt(private_key_bytes, aes_key_password)

    private_key_encrypted_b64 = base64.b64encode(
        iv_password + encrypted_private_key_password
    ).decode("utf-8")
    salt_password_b64 = base64.b64encode(salt_password).decode("utf-8")

    recovery_phrase = generate_recovery_phrase()
    aes_key_recovery, salt_recovery = phrase_to_key_and_salt(recovery_phrase)
    iv_recovery, encrypted_private_key_recovery = aes_encrypt(private_key_bytes, aes_key_recovery)

    recovery_key_encrypted_b64 = base64.b64encode(
        iv_recovery + encrypted_private_key_recovery
    ).decode("utf-8")
    salt_recovery_b64 = base64.b64encode(salt_recovery).decode("utf-8")

    fingerprint = hashlib.sha256(public_key_pem.encode()).hexdigest()
    gen_time = (time.time() - start_time) * 1000
    
    _log_crypto_action(user_id, "crypto_keygen",
        f"RSA-2048 generated | Fingerprint: {fingerprint[:32]}... | "
        f"PBKDF2: {PBKDF2_ITERATIONS} iterations, SHA256 | "
        f"Private key encrypted with AES-256-CFB | Time: {gen_time:.2f}ms")

    return {
        "public_key": public_key_pem,
        "private_key_encrypted": private_key_encrypted_b64,
        "private_key_salt": salt_password_b64,
        "recovery_phrase": recovery_phrase,
        "recovery_key_encrypted": recovery_key_encrypted_b64,
        "recovery_salt": salt_recovery_b64,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  5. RÉCUPÉRATION DE LA CLÉ PRIVÉE RSA
# ─────────────────────────────────────────────────────────────────────────────

def load_private_key_with_password(user: dict, password: str, user_id=None):
    start_time = time.time()
    
    try:
        salt = base64.b64decode(user["private_key_salt"])
        raw = base64.b64decode(user["private_key_encrypted"])
        iv = raw[:16]
        encrypted_data = raw[16:]

        pbkdf_start = time.time()
        aes_key = derive_key_from_password(password, salt)
        pbkdf_time = (time.time() - pbkdf_start) * 1000

        decrypt_start = time.time()
        private_key_bytes = aes_decrypt(encrypted_data, aes_key, iv)
        decrypt_time = (time.time() - decrypt_start) * 1000

        private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
        
        total_time = (time.time() - start_time) * 1000
        
        _log_crypto_action(user_id, "crypto_load_private",
            f"Private key loaded | PBKDF2: {pbkdf_time:.2f}ms ({PBKDF2_ITERATIONS} iterations, SHA256) | "
            f"AES-256-CFB decrypt: {decrypt_time:.2f}ms | Total: {total_time:.2f}ms")
        
        return private_key
    except Exception as e:
        _log_crypto_action(user_id, "crypto_load_private",
            f"Failed to load private key | Error: {str(e)}")
        raise ValueError("Mot de passe incorrect ou clé corrompue.")


def load_private_key_with_recovery(user: dict, recovery_phrase: str, user_id=None):
    start_time = time.time()
    
    try:
        salt = base64.b64decode(user["recovery_salt"])
        raw = base64.b64decode(user["recovery_key_encrypted"])
        iv = raw[:16]
        encrypted_data = raw[16:]

        aes_key = derive_key_from_password(recovery_phrase, salt)
        private_key_bytes = aes_decrypt(encrypted_data, aes_key, iv)
        private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
        
        total_time = (time.time() - start_time) * 1000
        
        _log_crypto_action(user_id, "crypto_load_recovery",
            f"Private key recovered via recovery phrase | Time: {total_time:.2f}ms")
        
        return private_key
    except Exception:
        _log_crypto_action(user_id, "crypto_load_recovery",
            f"Failed to recover private key | Invalid recovery phrase")
        raise ValueError("Phrase de récupération incorrecte ou clé corrompue.")


def load_public_key(user: dict):
    return serialization.load_pem_public_key(user["public_key"].encode("utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
#  6. CHANGEMENT DE MOT DE PASSE
# ─────────────────────────────────────────────────────────────────────────────

def change_password(user: dict, old_password: str, new_password: str, user_id=None) -> dict:
    start_time = time.time()
    
    private_key_obj = load_private_key_with_password(user, old_password, user_id)

    private_key_bytes = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    new_salt = os.urandom(16)
    new_aes_key = derive_key_from_password(new_password, new_salt)
    new_iv, new_encrypted = aes_encrypt(private_key_bytes, new_aes_key)

    total_time = (time.time() - start_time) * 1000
    
    _log_crypto_action(user_id, "crypto_password_change",
        f"Password changed | New salt generated | "
        f"Private key re-encrypted with AES-256-CFB | Time: {total_time:.2f}ms")

    return {
        "private_key_encrypted": base64.b64encode(new_iv + new_encrypted).decode("utf-8"),
        "private_key_salt": base64.b64encode(new_salt).decode("utf-8"),
    }


def reset_password_with_recovery(user: dict, recovery_phrase: str, new_password: str, user_id=None) -> dict:
    start_time = time.time()
    
    private_key_obj = load_private_key_with_recovery(user, recovery_phrase, user_id)

    private_key_bytes = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    new_salt = os.urandom(16)
    new_aes_key = derive_key_from_password(new_password, new_salt)
    new_iv, new_encrypted = aes_encrypt(private_key_bytes, new_aes_key)

    total_time = (time.time() - start_time) * 1000
    
    _log_crypto_action(user_id, "crypto_password_reset",
        f"Password reset via recovery phrase | New password encrypted with AES-256-CFB | Time: {total_time:.2f}ms")

    return {
        "private_key_encrypted": base64.b64encode(new_iv + new_encrypted).decode("utf-8"),
        "private_key_salt": base64.b64encode(new_salt).decode("utf-8"),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  7. CHIFFREMENT D'UN FICHIER (upload)
# ─────────────────────────────────────────────────────────────────────────────

def encrypt_file(file_data: bytes, public_key_pem: str, user_id=None) -> dict:
    start_time = time.time()
    
    sha256_hash = hashlib.sha256(file_data).hexdigest()
    file_size = len(file_data)

    aes_key = os.urandom(AES_KEY_SIZE)
    aes_key_b64 = base64.b64encode(aes_key).decode()

    iv, encrypted_file = aes_encrypt(file_data, aes_key)

    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode()

    total_time = (time.time() - start_time) * 1000
    
    _log_crypto_action(user_id, "crypto_encrypt",
        f"Hybrid encryption | File: {file_size} bytes | "
        f"SHA256: {sha256_hash[:16]}... | "
        f"AES-256 key: {aes_key_b64[:16]}... | "
        f"RSA-OAEP (SHA256) | IV: {base64.b64encode(iv).decode()[:16]}... | "
        f"Time: {total_time:.2f}ms")

    return {
        "encrypted_file": encrypted_file,
        "encrypted_aes_key": encrypted_aes_key_b64,
        "iv": base64.b64encode(iv).decode("utf-8"),
        "sha256_hash": sha256_hash,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  8. DÉCHIFFREMENT D'UN FICHIER (download)
# ─────────────────────────────────────────────────────────────────────────────

def decrypt_file(encrypted_file: bytes, file_record: dict, private_key, user_id=None) -> bytes:
    start_time = time.time()
    
    encrypted_aes_key = base64.b64decode(file_record["encrypted_aes_key"])
    
    rsa_start = time.time()
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    rsa_time = (time.time() - rsa_start) * 1000

    iv = base64.b64decode(file_record["iv"])
    aes_start = time.time()
    original_file = aes_decrypt(encrypted_file, aes_key, iv)
    aes_time = (time.time() - aes_start) * 1000

    computed_hash = hashlib.sha256(original_file).hexdigest()
    
    total_time = (time.time() - start_time) * 1000
    
    if computed_hash != file_record["sha256_hash"]:
        _log_crypto_action(user_id, "crypto_decrypt",
            f"Integrity check FAILED | Expected: {file_record['sha256_hash'][:16]}... | "
            f"Got: {computed_hash[:16]}... | Time: {total_time:.2f}ms")
        raise ValueError("Intégrité du fichier compromise : le fichier a été modifié !")

    _log_crypto_action(user_id, "crypto_decrypt",
        f"Hybrid decryption | RSA-OAEP: {rsa_time:.2f}ms | "
        f"AES-256-CFB: {aes_time:.2f}ms | "
        f"SHA256 integrity: OK ({computed_hash[:16]}...) | "
        f"Original size: {len(original_file)} bytes | Total: {total_time:.2f}ms")

    return original_file


# ─────────────────────────────────────────────────────────────────────────────
#  9. SIGNATURE ET VÉRIFICATION RSA
# ─────────────────────────────────────────────────────────────────────────────

def sign_file(file_data: bytes, private_key, user_id=None) -> str:
    start_time = time.time()
    
    file_hash = hashlib.sha256(file_data).hexdigest()
    
    signature = private_key.sign(
        file_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    
    total_time = (time.time() - start_time) * 1000
    
    _log_crypto_action(user_id, "crypto_sign",
        f"RSA-PSS signature | File SHA256: {file_hash[:16]}... | "
        f"Signature size: {len(signature)} bytes | Time: {total_time:.2f}ms")
    
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(file_data: bytes, signature_b64: str, public_key, user_id=None) -> bool:
    start_time = time.time()
    
    try:
        signature = base64.b64decode(signature_b64)
        file_hash = hashlib.sha256(file_data).hexdigest()
        
        public_key.verify(
            signature,
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        
        total_time = (time.time() - start_time) * 1000
        
        _log_crypto_action(user_id, "crypto_verify",
            f"RSA-PSS signature verification SUCCESS | "
            f"File SHA256: {file_hash[:16]}... | Time: {total_time:.2f}ms")
        return True
    except Exception as e:
        total_time = (time.time() - start_time) * 1000
        _log_crypto_action(user_id, "crypto_verify",
            f"RSA-PSS signature verification FAILED | Error: {str(e)} | Time: {total_time:.2f}ms")
        return False


# ─────────────────────────────────────────────────────────────────────────────
#  10. PARTAGE DE FICHIER
# ─────────────────────────────────────────────────────────────────────────────

def reencrypt_aes_key(
    file_record: dict,
    owner_private_key,
    recipient_public_key_pem: str,
    user_id=None
) -> str:
    start_time = time.time()
    
    encrypted_aes_key = base64.b64decode(file_record["encrypted_aes_key"])
    
    decrypt_start = time.time()
    aes_key = owner_private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    decrypt_time = (time.time() - decrypt_start) * 1000

    recipient_public_key = serialization.load_pem_public_key(
        recipient_public_key_pem.encode("utf-8")
    )
    
    encrypt_start = time.time()
    encrypted_for_recipient = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    encrypt_time = (time.time() - encrypt_start) * 1000
    
    total_time = (time.time() - start_time) * 1000
    aes_key_b64 = base64.b64encode(aes_key).decode()
    
    _log_crypto_action(user_id, "crypto_share",
        f"Key re-encryption for sharing | "
        f"Decrypt AES key (owner RSA): {decrypt_time:.2f}ms | "
        f"Encrypt AES key (recipient RSA): {encrypt_time:.2f}ms | "
        f"AES key: {aes_key_b64[:16]}... | Total: {total_time:.2f}ms")

    return base64.b64encode(encrypted_for_recipient).decode("utf-8")


def decrypt_shared_file(
    encrypted_file: bytes,
    shared_record: dict,
    file_record: dict,
    recipient_private_key,
    user_id=None
) -> bytes:
    start_time = time.time()
    
    encrypted_aes_key = base64.b64decode(shared_record["encrypted_aes_key_for_recipient"])
    
    rsa_start = time.time()
    aes_key = recipient_private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    rsa_time = (time.time() - rsa_start) * 1000

    iv = base64.b64decode(file_record["iv"])
    aes_start = time.time()
    original_file = aes_decrypt(encrypted_file, aes_key, iv)
    aes_time = (time.time() - aes_start) * 1000

    computed_hash = hashlib.sha256(original_file).hexdigest()
    
    total_time = (time.time() - start_time) * 1000
    
    if computed_hash != file_record["sha256_hash"]:
        _log_crypto_action(user_id, "crypto_decrypt_shared",
            f"Shared file integrity FAILED | Expected: {file_record['sha256_hash'][:16]}... | "
            f"Got: {computed_hash[:16]}... | Time: {total_time:.2f}ms")
        raise ValueError("Intégrité du fichier compromise !")

    _log_crypto_action(user_id, "crypto_decrypt_shared",
        f"Shared file decryption | RSA-OAEP: {rsa_time:.2f}ms | "
        f"AES-256-CFB: {aes_time:.2f}ms | "
        f"SHA256 integrity: OK | Total: {total_time:.2f}ms")

    return original_file