"""
auth.py  —  Authentication Module (Flask Blueprint)
=====================================================
Provides JWT-based authentication with signup (invite-key gated) and login.

Endpoints:
  POST /auth/signup   — Create new user (requires invite_key = "1913")
  POST /auth/login    — Authenticate and receive JWT token
  GET  /auth/me       — Return current user profile (requires auth)

Security:
  - Passwords hashed with bcrypt (via passlib)
  - JWT tokens with 24h expiry
  - Invite key validation prevents open registration
"""

from __future__ import annotations

import logging
import functools
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
import bcrypt
from flask import Blueprint, request, jsonify, g

from config import JWT_SECRET_KEY, JWT_EXPIRATION_HOURS, INVITE_KEY

log = logging.getLogger("AUTH")

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# ──────────────────────────────────────────────────────────────────────────────
# PASSWORD HASHING
# ──────────────────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            password_hash.encode("utf-8"),
        )
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# JWT TOKEN MANAGEMENT
# ──────────────────────────────────────────────────────────────────────────────

def generate_token(user: dict) -> str:
    """
    Generate a JWT token for an authenticated user.
    Payload includes: user_id, username, email, role, exp
    """
    now = datetime.now(timezone.utc)
    payload = {
        "user_id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user.get("role", "analyst"),
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRATION_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")


def decode_token(token: str) -> Optional[dict]:
    """
    Decode and validate a JWT token.
    Returns the payload dict on success, None on failure.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        log.warning("[AUTH] Token expired")
        return None
    except jwt.InvalidTokenError as exc:
        log.warning(f"[AUTH] Invalid token: {exc}")
        return None


# ──────────────────────────────────────────────────────────────────────────────
# AUTH DECORATOR  (@require_auth)
# ──────────────────────────────────────────────────────────────────────────────

def require_auth(f):
    """
    Flask decorator that enforces JWT authentication.

    Usage:
        @app.route("/protected")
        @require_auth
        def protected_route():
            user = g.current_user  # attached by decorator
            ...

    Expects header:  Authorization: Bearer <token>
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({
                "error": "Missing or invalid Authorization header",
                "hint": "Use: Authorization: Bearer <token>",
            }), 401

        token = auth_header[7:]  # strip "Bearer "
        payload = decode_token(token)

        if payload is None:
            return jsonify({"error": "Invalid or expired token"}), 401

        # Attach user info to Flask's request-local g object
        g.current_user = {
            "user_id": payload["user_id"],
            "username": payload["username"],
            "email": payload["email"],
            "role": payload["role"],
        }

        return f(*args, **kwargs)
    return decorated


# ──────────────────────────────────────────────────────────────────────────────
# SIGNUP ENDPOINT
# ──────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/signup", methods=["POST"])
def signup():
    """
    POST /auth/signup
    Create a new user account (gated by invite key).

    Body:
      {
        "username": "...",
        "email": "...",
        "password": "...",
        "invite_key": "1913"
      }

    Response 201: { "message": "...", "user": {...} }
    Response 400: { "error": "..." }
    Response 403: { "error": "Invalid invite key" }
    Response 409: { "error": "Username or email already exists" }
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON body received"}), 400

    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    invite_key = (data.get("invite_key") or "").strip()

    # ── Validation ───────────────────────────────────────────────────────────
    if not username or not email or not password:
        return jsonify({"error": "username, email, and password are required"}), 400

    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400

    if "@" not in email or "." not in email:
        return jsonify({"error": "Invalid email format"}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    # ── Invite Key Check ─────────────────────────────────────────────────────
    if invite_key != INVITE_KEY:
        return jsonify({"error": "Invalid invite key"}), 403

    # ── Create User ──────────────────────────────────────────────────────────
    from db import sync_create_user, sync_get_user_by_email, sync_get_user_by_username

    # Check for existing user
    if sync_get_user_by_email(email):
        return jsonify({"error": "Email already registered"}), 409

    if sync_get_user_by_username(username):
        return jsonify({"error": "Username already taken"}), 409

    pw_hash = hash_password(password)
    user = sync_create_user(username, email, pw_hash)

    if not user:
        return jsonify({"error": "Failed to create user (database error)"}), 500

    log.info(f"[AUTH] New user registered: {username} ({email})")

    return jsonify({
        "message": "Account created successfully",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
        },
    }), 201


# ──────────────────────────────────────────────────────────────────────────────
# LOGIN ENDPOINT
# ──────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["POST"])
def login():
    """
    POST /auth/login
    Authenticate a user and return a JWT token.

    Body:
      {
        "identifier": "email_or_username",
        "password": "..."
      }

    Response 200: { "token": "...", "user": {...} }
    Response 400: { "error": "..." }
    Response 401: { "error": "Invalid credentials" }
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON body received"}), 400

    identifier = (data.get("identifier") or "").strip()
    password = data.get("password") or ""

    if not identifier or not password:
        return jsonify({"error": "identifier and password are required"}), 400

    # ── Lookup User ──────────────────────────────────────────────────────────
    from db import sync_get_user_by_email, sync_get_user_by_username, sync_update_last_login

    # Try email first, then username
    user = sync_get_user_by_email(identifier.lower())
    if not user:
        user = sync_get_user_by_username(identifier)

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    if not user.get("is_active", True):
        return jsonify({"error": "Account is deactivated"}), 403

    # ── Verify Password ─────────────────────────────────────────────────────
    if not verify_password(password, user["password_hash"]):
        return jsonify({"error": "Invalid credentials"}), 401

    # ── Generate Token ───────────────────────────────────────────────────────
    token = generate_token(user)

    # Update last login timestamp
    sync_update_last_login(user["id"])

    log.info(f"[AUTH] Login successful: {user['username']}")

    return jsonify({
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
        },
    }), 200


# ──────────────────────────────────────────────────────────────────────────────
# ME ENDPOINT  (verify token + get profile)
# ──────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/me", methods=["GET"])
@require_auth
def me():
    """
    GET /auth/me
    Returns the current authenticated user's profile.
    Requires: Authorization: Bearer <token>
    """
    return jsonify({"user": g.current_user}), 200
