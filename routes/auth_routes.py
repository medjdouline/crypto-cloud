"""
routes/auth_routes.py
Routes : /login  /register  /logout  /recovery  /change-password
Sécurités : reCAPTCHA v2, CSRF, brute force, validation forte.
"""

# ── Imports ───────────────────────────────────────────────────────────────────
import requests                          # FIX 1 : manquait
from flask import (
    Blueprint, render_template, request,
    redirect, url_for, session, flash, jsonify
)
from services.auth_service  import register_user, login_user
from database.db             import add_log, get_user_by_id, get_user_by_username
from services.crypto_service import load_private_key_with_password, load_public_key
from config import (                     # FIX 2 : manquait
    RECAPTCHA_SECRET_KEY,
    RECAPTCHA_VERIFY_URL,
    RECAPTCHA_SITE_KEY
)

auth_bp = Blueprint("auth", __name__)


# ════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════

def verify_recaptcha(token):
    """
    Envoie le token à l'API Google et retourne True si humain.
    En cas d'erreur réseau on bloque par sécurité.
    """
    if not token:
        return False
    try:
        response = requests.post(RECAPTCHA_VERIFY_URL, data={
            "secret":   RECAPTCHA_SECRET_KEY,
            "response": token,
            "remoteip": request.remote_addr
        }, timeout=5)
        return response.json().get("success", False)
    except Exception:
        return False          # API Google inaccessible → on bloque


# ════════════════════════════════════════════════
# Routes
# ════════════════════════════════════════════════

@auth_bp.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("auth.login"))


# ── Connexion ─────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "GET":
        # FIX 4 : toujours passer recaptcha_site_key au template
        return render_template("login.html",
            recaptcha_site_key=RECAPTCHA_SITE_KEY
        )

    # ── POST ──────────────────────────────────────────────────────────────────

    # FIX 3 : reCAPTCHA vérifié EN PREMIER, avant login_user()
    recaptcha_token = request.form.get("g-recaptcha-response", "")
    if not verify_recaptcha(recaptcha_token):
        flash("Vérification anti-robot échouée. Cochez la case reCAPTCHA.", "error")
        return render_template("login.html",          # FIX 3 : plus de "..."
            recaptcha_site_key=RECAPTCHA_SITE_KEY
        )

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    ok, result = login_user(username, password)

    if not ok:
        flash(result, "error")
        return render_template("login.html",
            recaptcha_site_key=RECAPTCHA_SITE_KEY
        )

    # Connexion réussie → ouvrir la session
    session["user_id"]  = result["id"]
    session["username"] = result["username"]
    session["role"]     = result["role"]
    session["password"] = password   # pour les opérations crypto RSA

    # Vérification optionnelle de la clé privée RSA
    try:
        load_private_key_with_password(result, password)
        session["crypto_ready"] = True
    except ValueError as e:
        flash(f"Attention : problème de clé cryptographique : {e}", "warning")
        session["crypto_ready"] = False

    add_log(result["id"], "login", ip=request.remote_addr)
    return redirect(url_for("dashboard"))


# ── Inscription ───────────────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "GET":
        return render_template("register.html",
            recaptcha_site_key=RECAPTCHA_SITE_KEY
        )

    # ── Vérification reCAPTCHA ─────────────────────────────
    recaptcha_token = request.form.get("g-recaptcha-response", "")
    if not verify_recaptcha(recaptcha_token):
        flash("Vérification anti-robot échouée.", "error")
        return render_template("register.html",
            recaptcha_site_key=RECAPTCHA_SITE_KEY
        )

    # ── Données utilisateur ────────────────────────────────
    username = request.form.get("username", "").strip()
    email    = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    confirm  = request.form.get("confirm_password", "")

    if password != confirm:
        flash("Les mots de passe ne correspondent pas.", "error")
        return render_template("register.html",
            recaptcha_site_key=RECAPTCHA_SITE_KEY
        )

    if len(password) < 8:
        flash("Le mot de passe doit faire au moins 8 caractères.", "error")
        return render_template("register.html",
            recaptcha_site_key=RECAPTCHA_SITE_KEY
        )

    success, user_id, recovery_phrase = register_user(username, email, password)

    if success:
        add_log(user_id, "register",
                f"Nouvel utilisateur : {username}", request.remote_addr)
        return render_template("recovery_phrase_display.html",
                               recovery_phrase=recovery_phrase)
    else:
        flash(user_id, "error")
        return render_template("register.html",
            recaptcha_site_key=RECAPTCHA_SITE_KEY
        )

# ── Déconnexion ───────────────────────────────────────────────────────────────

@auth_bp.route("/logout")
def logout():
    if "user_id" in session:
        user = get_user_by_id(session["user_id"])
        if user:
            add_log(session["user_id"], "logout", ip=request.remote_addr)
        else:
            add_log(None, "logout", ip=request.remote_addr)
    session.clear()
    flash("Déconnecté avec succès.", "success")
    return redirect(url_for("auth.login"))


# ── Récupération de compte ────────────────────────────────────────────────────

@auth_bp.route("/recovery", methods=["GET", "POST"])
def recovery():
    if request.method == "GET":
        return render_template("recovery.html")

    username         = request.form.get("username", "").strip()
    recovery_phrase  = request.form.get("recovery_phrase", "").strip()
    new_password     = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if new_password != confirm_password:
        flash("Les mots de passe ne correspondent pas.", "error")
        return render_template("recovery.html")

    if len(new_password) < 6:
        flash("Le mot de passe doit faire au moins 6 caractères.", "error")
        return render_template("recovery.html")

    from services.auth_service  import hash_password
    from services.crypto_service import reset_password_with_recovery
    from database.db             import execute

    user = get_user_by_username(username)
    if not user:
        flash("Utilisateur introuvable.", "error")
        return render_template("recovery.html")

    try:
        new_keys = reset_password_with_recovery(
            user, recovery_phrase, new_password, user_id=user["id"]
        )
        execute("""
            UPDATE users
            SET private_key_encrypted = ?, private_key_salt = ?
            WHERE id = ?
        """, (new_keys["private_key_encrypted"],
              new_keys["private_key_salt"],
              user["id"]))

        new_hash = hash_password(new_password)
        execute("UPDATE users SET password_hash = ? WHERE id = ?",
                (new_hash, user["id"]))

        add_log(user["id"], "password_reset",
                "Mot de passe réinitialisé via phrase de récupération")
        flash("Mot de passe réinitialisé avec succès !", "success")
        return redirect(url_for("auth.login"))

    except ValueError as e:
        flash(f"Erreur : {e}", "error")
        return render_template("recovery.html")


# ── Changement de mot de passe ────────────────────────────────────────────────

@auth_bp.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    if request.method == "GET":
        return render_template("change_password.html")

    old_password     = request.form.get("old_password", "")
    new_password     = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if new_password != confirm_password:
        flash("Les nouveaux mots de passe ne correspondent pas.", "error")
        return render_template("change_password.html")

    if len(new_password) < 6:
        flash("Le mot de passe doit faire au moins 6 caractères.", "error")
        return render_template("change_password.html")

    from services.auth_service  import check_password, hash_password
    from services.crypto_service import change_password as crypto_change_password
    from database.db             import execute

    user = get_user_by_id(session["user_id"])
    if not check_password(old_password, user["password_hash"]):
        flash("Ancien mot de passe incorrect.", "error")
        return render_template("change_password.html")

    # Mettre à jour le hash bcrypt
    execute("UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(new_password), user["id"]))

    # Rechiffrer la clé privée RSA avec le nouveau mot de passe
    try:
        new_keys = crypto_change_password(
            user, old_password, new_password, user_id=user["id"]
        )
        execute("""
            UPDATE users
            SET private_key_encrypted = ?, private_key_salt = ?
            WHERE id = ?
        """, (new_keys["private_key_encrypted"],
              new_keys["private_key_salt"],
              user["id"]))

        add_log(user["id"], "password_change", "Mot de passe changé avec succès")
        flash("Mot de passe changé avec succès !", "success")
        session["password"] = new_password    # mettre à jour en session
        return redirect(url_for("dashboard"))

    except ValueError as e:
        flash(f"Erreur cryptographique : {e}", "error")
        return render_template("change_password.html")