"""
admin_routes.py  v2
--------------------
Routes Flask réservées à l'administrateur.
Améliorations v2 : stats complètes (nb fichiers, espace, téléchargements par user)
"""

import os
import sys
import shutil
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from flask import (
    Blueprint, request, session,
    redirect, url_for, flash, render_template
)
from config import STORAGE_DIR, KEYS_DIR
from database.db import (
    get_all_users, get_quota, get_user_by_id,
    set_user_active, delete_user,
    get_all_logs, get_files_by_user,
    fetch_all, add_log
)
from services.quota_service import set_user_quota
from services.file_service  import get_download_count

admin_bp = Blueprint("admin", __name__)


def _require_admin():
    return session.get("user_id") and session.get("role") == "admin"


# ── Stats globales ─────────────────────────────────────────────────────────────

def _build_user_stats(raw_users):
    """
    Construit la liste enrichie des utilisateurs avec :
    - quota utilisé / max / pourcentage
    - nombre de fichiers
    - nombre total de téléchargements reçus sur ses fichiers
    """
    users = []
    for u in raw_users:
        quota    = get_quota(u["id"])
        used     = quota["quota_used"] if quota else 0
        maxi     = quota["quota_max"]  if quota else 0
        pct      = round((used / maxi) * 100) if maxi > 0 else 0
        files    = get_files_by_user(u["id"])

        # Total téléchargements sur tous les fichiers de cet utilisateur
        total_downloads = sum(get_download_count(f["id"]) for f in files)

        users.append({
            "id"              : u["id"],
            "username"        : u["username"],
            "email"           : u["email"],
            "role"            : u["role"],
            "is_active"       : u["is_active"],
            "created_at"      : u["created_at"],
            "quota_used_mb"   : round(used / (1024 * 1024), 2),
            "quota_max_mb"    : round(maxi / (1024 * 1024), 2),
            "quota_percent"   : pct,
            "nb_files"        : len(files),
            "total_downloads" : total_downloads,
        })
    return users


def _build_global_stats(raw_users):
    """Stats globales affichées en haut de la page admin."""
    total_files    = 0
    total_size     = 0
    total_downloads = 0

    for u in raw_users:
        files       = get_files_by_user(u["id"])
        quota       = get_quota(u["id"])
        total_files += len(files)
        total_size  += quota["quota_used"] if quota else 0
        total_downloads += sum(get_download_count(f["id"]) for f in files)

    # Utilisateur qui utilise le plus d'espace
    top_user = None
    if raw_users:
        top = max(
            raw_users,
            key=lambda u: (get_quota(u["id"])["quota_used"]
                           if get_quota(u["id"]) else 0)
        )
        top_quota = get_quota(top["id"])
        top_user  = {
            "username"      : top["username"],
            "quota_used_mb" : round(top_quota["quota_used"] / (1024*1024), 2)
                              if top_quota else 0
        }

    return {
        "total_users"      : len(raw_users),
        "total_files"      : total_files,
        "total_size_mb"    : round(total_size / (1024 * 1024), 2),
        "total_downloads"  : total_downloads,
        "top_user"         : top_user,
    }


# ── Page admin ────────────────────────────────────────────────────────────────

@admin_bp.route("/admin")
def admin_dashboard():
    if not _require_admin():
        flash("Accès réservé à l'administrateur.", "error")
        return redirect(url_for("auth.login"))

    raw_users = get_all_users()
    users     = _build_user_stats(raw_users)
    stats     = _build_global_stats(raw_users)
    logs      = get_all_logs()

    return render_template(
        "admin.html",
        users          = users,
        total_files    = stats["total_files"],
        total_size_mb  = stats["total_size_mb"],
        total_downloads= stats["total_downloads"],
        top_user       = stats["top_user"],
        logs           = logs
    )

# routes/admin_routes.py
@admin_bp.route("/logs")
def logs():
    """Page indépendante pour les logs système."""
    if session.get("role") != "admin":
        flash("Accès non autorisé.", "error")
        return redirect(url_for("dashboard"))
    
    from database.db import get_all_logs
    logs = get_all_logs()
    
    return render_template("admin_logs.html", logs=logs)
@admin_bp.route("/crypto")
def crypto_admin():
    """Page d'administration crypto."""
    if session.get("role") != "admin":
        flash("Accès non autorisé.", "error")
        return redirect(url_for("dashboard"))
    
    from database.db import fetch_all
    import hashlib
    
    # Récupérer tous les utilisateurs avec leurs clés
    users = fetch_all("""
        SELECT id, username, email, role, is_active, created_at,
               public_key, private_key_encrypted, private_key_salt,
               recovery_key_encrypted, recovery_salt
        FROM users
        ORDER BY created_at DESC
    """)
    
    # Convertir en dictionnaires et calculer l'empreinte
    users_list = []
    for user in users:
        user_dict = dict(user)
        
        if user_dict.get("public_key"):
            fingerprint = hashlib.sha256(user_dict["public_key"].encode()).hexdigest()
            user_dict["key_fingerprint"] = fingerprint
        else:
            user_dict["key_fingerprint"] = None
        
        users_list.append(user_dict)
    
    # Statistiques
    total_users = len(users_list)
    total_files_encrypted = fetch_all("SELECT COUNT(*) as cnt FROM files")[0]["cnt"]
    total_shares = fetch_all("SELECT COUNT(*) as cnt FROM shared_files")[0]["cnt"]
    
    # Récupérer TOUS les logs crypto (pas seulement ceux avec action LIKE 'crypto_%')
    # Mais aussi les logs normaux qui contiennent des infos crypto
    crypto_logs = fetch_all("""
        SELECT l.*, u.username
        FROM logs l
        LEFT JOIN users u ON l.user_id = u.id
        WHERE l.action LIKE 'crypto_%' 
           OR l.action IN ('upload', 'download', 'share')
        ORDER BY l.timestamp DESC
        LIMIT 200
    """)
    
    # Convertir en dictionnaires
    crypto_logs_list = []
    for log in crypto_logs:
        log_dict = dict(log)
        crypto_logs_list.append(log_dict)
    
    crypto_ops_total = len(crypto_logs_list)
    total_keys = len([u for u in users_list if u.get("public_key")])
    
    return render_template("admin_crypto.html",
        users=users_list,
        total_users=total_users,
        total_files_encrypted=total_files_encrypted,
        total_shares=total_shares,
        crypto_logs=crypto_logs_list,
        crypto_ops_total=crypto_ops_total,
        total_keys=total_keys
    )
# ── Suspendre / Réactiver ─────────────────────────────────────────────────────

@admin_bp.route("/admin/toggle_user/<int:user_id>", methods=["POST"])
def toggle_user(user_id):
    if not _require_admin():
        flash("Accès refusé.", "error")
        return redirect(url_for("auth.login"))

    user = get_user_by_id(user_id)
    if not user:
        flash("Utilisateur introuvable.", "error")
        return redirect(url_for("admin.admin_dashboard"))
    if user["role"] == "admin":
        flash("Impossible de suspendre un administrateur.", "error")
        return redirect(url_for("admin.admin_dashboard"))

    nouvel_etat  = 0 if user["is_active"] else 1
    set_user_active(user_id, nouvel_etat)
    label = "réactivé" if nouvel_etat else "suspendu"

    add_log(session["user_id"], "login",
            f"Admin : '{user['username']}' {label}",
            request.remote_addr)
    flash(f"✅ Compte '{user['username']}' {label}.", "success")
    return redirect(url_for("admin.admin_dashboard"))


# ── Supprimer un utilisateur ──────────────────────────────────────────────────

@admin_bp.route("/admin/delete_user/<int:user_id>", methods=["POST"])
def delete_user_route(user_id):
    if not _require_admin():
        flash("Accès refusé.", "error")
        return redirect(url_for("auth.login"))

    user = get_user_by_id(user_id)
    if not user:
        flash("Utilisateur introuvable.", "error")
        return redirect(url_for("admin.admin_dashboard"))
    if user["role"] == "admin":
        flash("Impossible de supprimer un administrateur.", "error")
        return redirect(url_for("admin.admin_dashboard"))

    delete_user(user_id)

    # Suppression des dossiers sur disque
    for base_dir in [STORAGE_DIR, KEYS_DIR]:
        user_dir = os.path.join(base_dir, f"user_{user_id}")
        if os.path.exists(user_dir):
            shutil.rmtree(user_dir)

    add_log(session["user_id"], "delete",
            f"Admin : '{user['username']}' supprimé définitivement",
            request.remote_addr)
    flash(f"🗑️ Compte '{user['username']}' supprimé.", "success")
    return redirect(url_for("admin.admin_dashboard"))


# ── Modifier quota ────────────────────────────────────────────────────────────

@admin_bp.route("/admin/set_quota", methods=["POST"])
def set_quota_route():
    if not _require_admin():
        flash("Accès refusé.", "error")
        return redirect(url_for("auth.login"))

    user_id      = request.form.get("user_id",   type=int)
    new_quota_mb = request.form.get("new_quota", type=int)

    if not user_id or not new_quota_mb:
        flash("Données manquantes.", "error")
        return redirect(url_for("admin.admin_dashboard"))

    ok, message = set_user_quota(user_id, new_quota_mb)
    if ok:
        user = get_user_by_id(user_id)
        add_log(session["user_id"], "login",
                f"Admin : quota de '{user['username']}' → {new_quota_mb} MB",
                request.remote_addr)
        flash(f" Quota mis à jour : {new_quota_mb} MB.", "success")
    else:
        flash(f" {message}", "error")

    return redirect(url_for("admin.admin_dashboard"))