"""
file_validator.py
------------------
Validation des fichiers uploadés :
    1. Magic bytes  → vérifie le VRAI type du fichier (pas juste l'extension)
    2. Taille max   → bloque les fichiers trop gros

Pourquoi les magic bytes ?
    Un attaquant peut renommer virus.exe en virus.jpg
    → l'extension dit "jpg" mais les premiers octets trahissent que c'est un exe
    → on lit les vrais octets pour confirmer le type réel
"""

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from config import ALLOWED_EXTENSIONS

# ── Taille maximale par fichier ───────────────────────────────────────────────
MAX_FILE_SIZE_MB    = 50                        # modifiable dans config.py si besoin
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024


# ── Dictionnaire magic bytes ──────────────────────────────────────────────────
# Structure :
#   "extension" : [(offset, bytes_attendus), ...]
#
# offset  = position dans le fichier où lire (0 = début)
# bytes   = séquence d'octets qui identifie ce type de fichier
#
# Source : https://en.wikipedia.org/wiki/List_of_file_signatures

MAGIC_BYTES = {
    # Images
    "jpg"  : [(0, b"\xff\xd8\xff")],
    "jpeg" : [(0, b"\xff\xd8\xff")],
    "png"  : [(0, b"\x89PNG\r\n\x1a\n")],
    "gif"  : [(0, b"GIF87a"), (0, b"GIF89a")],
    "webp" : [(0, b"RIFF"), (8, b"WEBP")],
    "bmp"  : [(0, b"BM")],

    # Documents
    "pdf"  : [(0, b"%PDF")],
    "docx" : [(0, b"PK\x03\x04")],   # format ZIP (Office Open XML)
    "xlsx" : [(0, b"PK\x03\x04")],   # format ZIP
    "zip"  : [(0, b"PK\x03\x04")],

    # Texte — pas de magic bytes fixes, on vérifie juste que c'est lisible
    "txt"  : None,
    "csv"  : None,
    "md"   : None,
    "json" : None,

    # Vidéo
    "mp4"  : [(4, b"ftyp")],
    "avi"  : [(0, b"RIFF"), (8, b"AVI ")],

    # Audio
    "mp3"  : [(0, b"ID3"), (0, b"\xff\xfb"), (0, b"\xff\xf3")],
}

# Extensions DANGEREUSES — toujours bloquées même si renommées
DANGEROUS_EXTENSIONS = {
    "exe", "bat", "cmd", "sh", "ps1", "vbs",
    "js",  "php", "py",  "rb", "pl",  "jar",
    "dll", "so",  "msi", "com", "scr", "pif"
}


# ── Validation taille ─────────────────────────────────────────────────────────

def check_file_size(file_bytes: bytes) -> tuple[bool, str]:
    """
    Vérifie que le fichier ne dépasse pas MAX_FILE_SIZE_BYTES.

    Retourne (True, "ok") ou (False, message_erreur).
    """
    size = len(file_bytes)
    if size == 0:
        return False, "Le fichier est vide."
    if size > MAX_FILE_SIZE_BYTES:
        size_mb = round(size / (1024 * 1024), 2)
        return False, (
            f"Fichier trop grand : {size_mb} MB. "
            f"Limite autorisée : {MAX_FILE_SIZE_MB} MB."
        )
    return True, "ok"


# ── Validation extension ──────────────────────────────────────────────────────

def check_extension(filename: str) -> tuple[bool, str]:
    """
    Vérifie que l'extension est autorisée et non dangereuse.

    Retourne (True, ext) ou (False, message_erreur).
    """
    if "." not in filename:
        return False, "Le fichier n'a pas d'extension."

    ext = filename.rsplit(".", 1)[1].lower()

    if ext in DANGEROUS_EXTENSIONS:
        return False, (
            f"Extension '.{ext}' interdite pour des raisons de sécurité."
        )

    if ext not in ALLOWED_EXTENSIONS:
        return False, (
            f"Extension '.{ext}' non autorisée. "
            f"Formats acceptés : {', '.join(sorted(ALLOWED_EXTENSIONS))}."
        )

    return True, ext


# ── Validation magic bytes ────────────────────────────────────────────────────

def check_magic_bytes(file_bytes: bytes, ext: str) -> tuple[bool, str]:
    """
    Vérifie que les octets du fichier correspondent à son extension.
    Détecte les fichiers déguisés (ex: virus.exe renommé en virus.jpg).

    Retourne (True, "ok") ou (False, message_erreur).
    """
    # Extensions texte → pas de magic bytes, on vérifie que c'est du texte lisible
    if MAGIC_BYTES.get(ext) is None:
        return _check_is_text(file_bytes, ext)

    # Extension inconnue du dictionnaire → on accepte (pas de règle définie)
    if ext not in MAGIC_BYTES:
        return True, "ok"

    signatures = MAGIC_BYTES[ext]

    for sig in signatures:
        # Chaque signature est une liste de (offset, bytes_attendus)
        # Pour les formats avec plusieurs checks (ex: WEBP = RIFF + WEBP)
        if isinstance(sig, list):
            if all(_match_at(file_bytes, offset, expected)
                   for offset, expected in sig):
                return True, "ok"
        else:
            offset, expected = sig
            if _match_at(file_bytes, offset, expected):
                return True, "ok"

    return False, (
        f"Le contenu du fichier ne correspond pas à l'extension '.{ext}'. "
        f"Fichier potentiellement dangereux ou corrompu."
    )


def _match_at(data: bytes, offset: int, expected: bytes) -> bool:
    """Vérifie si `expected` est présent dans `data` à partir de `offset`."""
    end = offset + len(expected)
    if len(data) < end:
        return False
    return data[offset:end] == expected


def _check_is_text(file_bytes: bytes, ext: str) -> tuple[bool, str]:
    """
    Pour les fichiers texte (txt, csv, json...) :
    vérifie que le contenu est bien du texte UTF-8 lisible.
    """
    try:
        sample = file_bytes[:1024]  # on teste juste les 1024 premiers octets
        sample.decode("utf-8")
        return True, "ok"
    except UnicodeDecodeError:
        return False, (
            f"Le fichier '.{ext}' contient des données binaires "
            f"alors qu'un fichier texte est attendu."
        )


# ── Validation complète (fonction principale) ─────────────────────────────────

def validate_file(filename: str, file_bytes: bytes) -> tuple[bool, str]:
    """
    Effectue TOUTES les validations dans l'ordre :
        1. Extension autorisée et non dangereuse
        2. Taille acceptable
        3. Magic bytes cohérents avec l'extension

    C'est la seule fonction à appeler depuis file_service.py.

    Retourne (True, "ok") ou (False, message_erreur).
    """

    # 1. Extension
    ok, result = check_extension(filename)
    if not ok:
        return False, result
    ext = result

    # 2. Taille
    ok, message = check_file_size(file_bytes)
    if not ok:
        return False, message

    # 3. Magic bytes
    ok, message = check_magic_bytes(file_bytes, ext)
    if not ok:
        return False, message

    return True, "ok"