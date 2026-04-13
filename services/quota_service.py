"""
quota_service.py
-----------------
Gestion des quotas de stockage par utilisateur.
Toutes les tailles sont en OCTETS en interne.
"""

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from database.db import get_quota, update_quota_used, set_quota_max


# ── Vérification avant upload ─────────────────────────────────────────────────

def check_quota(user_id: int, file_size: int) -> tuple[bool, str]:
    """
    Vérifie si l'utilisateur a assez d'espace pour uploader un fichier.

    Retourne :
        (True,  "ok")                        → upload autorisé
        (False, "message d'erreur")          → upload bloqué
    """
    quota = get_quota(user_id)

    if quota is None:
        return False, "Quota introuvable pour cet utilisateur."

    espace_restant = quota["quota_max"] - quota["quota_used"]

    if file_size <= 0:
        return False, "Taille de fichier invalide."

    if file_size > espace_restant:
        restant_mb  = round(espace_restant  / (1024 * 1024), 2)
        fichier_mb  = round(file_size       / (1024 * 1024), 2)
        max_mb      = round(quota["quota_max"] / (1024 * 1024), 2)
        utilise_mb  = round(quota["quota_used"] / (1024 * 1024), 2)
        return False, (
            f"Quota insuffisant. "
            f"Fichier : {fichier_mb} MB — "
            f"Espace restant : {restant_mb} MB "
            f"({utilise_mb} / {max_mb} MB utilisés)."
        )

    return True, "ok"


# ── Mise à jour après opération ───────────────────────────────────────────────

def add_to_quota(user_id: int, file_size: int) -> bool:
    """
    Ajoute file_size octets au quota utilisé après un upload.
    Retourne True si succès, False si ça dépasse le max (sécurité).
    """
    return update_quota_used(user_id, +file_size)


def free_from_quota(user_id: int, file_size: int) -> bool:
    """
    Libère file_size octets du quota utilisé après une suppression.
    Retourne True si succès.
    """
    return update_quota_used(user_id, -file_size)


# ── Modification du quota max (admin) ─────────────────────────────────────────

def set_user_quota(user_id: int, new_quota_mb: int) -> tuple[bool, str]:
    """
    Modifie le quota maximum d'un utilisateur (action admin).

    Paramètre :
        new_quota_mb  →  nouveau quota en MB (ex: 200 pour 200 MB)

    Retourne (True, "ok") ou (False, message_erreur).
    """
    if new_quota_mb <= 0:
        return False, "Le quota doit être supérieur à 0 MB."

    quota = get_quota(user_id)
    if quota is None:
        return False, "Utilisateur introuvable."

    # On ne peut pas descendre en dessous de ce qui est déjà utilisé
    utilise_mb = round(quota["quota_used"] / (1024 * 1024), 2)
    if new_quota_mb < utilise_mb:
        return False, (
            f"Impossible : l'utilisateur utilise déjà {utilise_mb} MB. "
            f"Le nouveau quota doit être supérieur."
        )

    new_quota_bytes = new_quota_mb * 1024 * 1024
    set_quota_max(user_id, new_quota_bytes)
    return True, "ok"


# ── Stats pour l'affichage ────────────────────────────────────────────────────

def get_quota_stats(user_id: int) -> dict:
    """
    Retourne un dictionnaire avec toutes les infos de quota
    prêtes à être envoyées au template HTML.

    Exemple de retour :
    {
        "quota_used_bytes" : 52428800,
        "quota_max_bytes"  : 104857600,
        "quota_used_mb"    : 50.0,
        "quota_max_mb"     : 100.0,
        "quota_free_mb"    : 50.0,
        "quota_percent"    : 50,
        "is_full"          : False,
        "is_warning"       : False,   ← True si > 80%
        "is_critical"      : False,   ← True si > 95%
    }
    """
    quota = get_quota(user_id)

    if quota is None:
        return {
            "quota_used_bytes" : 0,
            "quota_max_bytes"  : 0,
            "quota_used_mb"    : 0,
            "quota_max_mb"     : 0,
            "quota_free_mb"    : 0,
            "quota_percent"    : 0,
            "is_full"          : False,
            "is_warning"       : False,
            "is_critical"      : False,
        }

    used  = quota["quota_used"]
    maxi  = quota["quota_max"]
    pct   = round((used / maxi) * 100) if maxi > 0 else 0

    return {
        "quota_used_bytes" : used,
        "quota_max_bytes"  : maxi,
        "quota_used_mb"    : round(used / (1024 * 1024), 2),
        "quota_max_mb"     : round(maxi / (1024 * 1024), 2),
        "quota_free_mb"    : round((maxi - used) / (1024 * 1024), 2),
        "quota_percent"    : pct,
        "is_full"          : pct >= 100,
        "is_warning"       : pct >= 80,
        "is_critical"      : pct >= 95,
    }