"""
file_routes.py
---------------
Routes Flask pour la gestion des fichiers.
POST /upload
GET  /download/<file_id>
POST /delete/<file_id>
POST /share
"""

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from flask import (
    Blueprint, request, session, redirect,
    url_for, flash, send_file, after_this_request,render_template
)
import io

from services.file_service import (
    upload_file, download_file,
    delete_file, share_file,
    list_user_files, list_shared_with_me
)

file_bp = Blueprint("files", __name__)


# ── Utilitaire : vérifier la session ─────────────────────────────────────────

def _get_current_user():
    """Retourne (user_id, password) depuis la session ou (None, None)."""
    user_id  = session.get("user_id")
    password = session.get("password")   # stocké en session par auth_routes
    return user_id, password


# ── Upload ────────────────────────────────────────────────────────────────────

@file_bp.route("/upload", methods=["POST"])
def upload():
    user_id, password = _get_current_user()
    if not user_id:
        return redirect(url_for("auth.login"))

    # Récupère le fichier envoyé par le formulaire HTML
    file_obj = request.files.get("file")
    if not file_obj or file_obj.filename == "":
        flash("Aucun fichier sélectionné.", "error")
        return redirect(url_for("dashboard"))

    ok, message = upload_file(
        user_id  = user_id,
        file_obj = file_obj,
        password = password,
        ip       = request.remote_addr
    )

    if ok:
        flash(f"✅ '{file_obj.filename}' chiffré et uploadé avec succès.", "success")
    else:
        flash(f"❌ Erreur : {message}", "error")

    return redirect(url_for("dashboard"))


# ── Download ──────────────────────────────────────────────────────────────────

@file_bp.route("/download/<int:file_id>")
def download(file_id):
    user_id, password = _get_current_user()
    if not user_id:
        return redirect(url_for("auth.login"))

    ok, result, original_name = download_file(
        user_id  = user_id,
        file_id  = file_id,
        password = password,
        ip       = request.remote_addr
    )

    if not ok:
        flash(f"❌ {result}", "error")
        return redirect(url_for("dashboard"))

    # Envoie le fichier déchiffré au navigateur comme téléchargement
    return send_file(
        io.BytesIO(result),
        download_name = original_name,
        as_attachment = True
    )


# ── Suppression ───────────────────────────────────────────────────────────────

@file_bp.route("/delete/<int:file_id>", methods=["POST"])
def delete(file_id):
    user_id, password = _get_current_user()
    if not user_id:
        return redirect(url_for("auth.login"))

    ok, message = delete_file(
        user_id = user_id,
        file_id = file_id,
        ip      = request.remote_addr
    )

    if ok:
        flash("🗑️ Fichier supprimé.", "success")
    else:
        flash(f"❌ {message}", "error")

    return redirect(url_for("dashboard"))


# ── Partage ───────────────────────────────────────────────────────────────────

@file_bp.route("/share", methods=["POST"])
def share():
    user_id, password = _get_current_user()
    if not user_id:
        return redirect(url_for("auth.login"))

    file_id            = request.form.get("file_id",    type=int)
    recipient_username = request.form.get("share_with", "").strip()

    if not file_id or not recipient_username:
        flash("Données manquantes pour le partage.", "error")
        return redirect(url_for("dashboard"))

    ok, message = share_file(
        owner_id           = user_id,
        file_id            = file_id,
        recipient_username = recipient_username,
        owner_password     = password,
        ip                 = request.remote_addr
    )

    if ok:
        flash(f" Fichier partagé avec '{recipient_username}'.", "success")
    else:
        flash(f" {message}", "error")

    return redirect(url_for("dashboard"))

@file_bp.route("/crypto-logs")
def crypto_logs():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    from database.db import get_connection
    user_id = session["user_id"]
    conn = get_connection()

    # Vérifier si l'utilisateur est admin
    is_admin = conn.execute(
        "SELECT role FROM users WHERE id = ?", 
        (user_id,)
    ).fetchone()[0] == 'admin'

    if is_admin:
        # === ADMIN : Voir TOUS les fichiers du système ===
        files = conn.execute("""
            SELECT 
                f.id, 
                f.original_name, 
                f.stored_name, 
                f.file_size,
                f.sha256_hash, 
                f.signature, 
                f.encrypted_aes_key, 
                f.iv, 
                f.uploaded_at,
                u.username as owner_username,
                'own' as file_type
            FROM files f
            JOIN users u ON f.owner_id = u.id
            ORDER BY f.uploaded_at DESC
        """).fetchall()


    else:
        # === UTILISATEUR NORMAL : ses fichiers + ceux partagés avec lui ===
        own_files = conn.execute("""
            SELECT 
                id, original_name, stored_name, file_size,
                sha256_hash, signature, encrypted_aes_key, iv, uploaded_at,
                'own' as file_type
            FROM files
            WHERE owner_id = ?
            ORDER BY uploaded_at DESC
        """, (user_id,)).fetchall()

        shared_files = conn.execute("""
            SELECT 
                f.id, 
                f.original_name, 
                f.stored_name, 
                f.file_size,
                f.sha256_hash, 
                f.signature, 
                s.encrypted_aes_key_for_recipient as encrypted_aes_key,
                f.iv, 
                f.uploaded_at,
                'shared' as file_type
            FROM shared_files s
            JOIN files f ON s.file_id = f.id
            WHERE s.shared_with = ?
            ORDER BY f.uploaded_at DESC
        """, (user_id,)).fetchall()

        files = list(own_files) + list(shared_files)
        files.sort(key=lambda x: x['uploaded_at'] if x.get('uploaded_at') else '', reverse=True)

    # === Logs (pour tout le monde : seulement ses propres actions) ===
    crypto_logs = conn.execute("""
        SELECT 
            l.id, l.action, l.details, l.ip, l.timestamp,
            u.username
        FROM logs l
        LEFT JOIN users u ON u.id = l.user_id
        WHERE l.user_id = ?
          AND l.action IN ('upload', 'download', 'share', 'delete')
        ORDER BY l.timestamp DESC
    """, (user_id,)).fetchall()

    conn.close()

    return render_template(
        "crypto_logs.html",
        files=files,
        crypto_logs=crypto_logs,
        is_admin=is_admin   # ← On passe cette info au template si besoin
    )