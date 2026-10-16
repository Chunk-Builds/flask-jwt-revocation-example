import os
import secrets
import warnings
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    get_jwt, get_jwt_identity, jwt_required,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()
jwt = JWTManager()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)


class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, unique=True, index=True)
    created_at = db.Column(
        db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

def create_app(test_config=None):
    app = Flask(__name__)
    secret = os.getenv("JWT_SECRET_KEY")
    if not secret:
        # Dev convenience only: a random per-process key, so tokens die on restart.
        warnings.warn("JWT_SECRET_KEY not set; using a random key for this process only.")
        secret = secrets.token_hex(32)
    app.config.update(
        SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///app.db"),
        JWT_SECRET_KEY=secret,
        JWT_ACCESS_TOKEN_EXPIRES=timedelta(minutes=15),
        JWT_REFRESH_TOKEN_EXPIRES=timedelta(days=30),
    )
    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    jwt.init_app(app)

    @jwt.token_in_blocklist_loader
    def is_revoked(_header, payload):
        jti = payload["jti"]
        return db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar() is not None

    @jwt.revoked_token_loader
    def revoked(_header, _payload):
        return jsonify(error="Token has been revoked"), 401

    @jwt.invalid_token_loader
    def invalid(reason):
        return jsonify(error=reason), 401

    @jwt.unauthorized_loader
    def missing(reason):
        return jsonify(error=reason), 401

    def tokens_for(user):
        identity = str(user.id)  # "sub" must be a string
        return {
            "access_token": create_access_token(identity=identity),
            "refresh_token": create_refresh_token(identity=identity),
        }

    @app.post("/auth/register")
    def register():
        data = request.get_json(silent=True) or {}
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        if not email or len(password) < 8:
            return jsonify(error="email and an 8+ char password are required"), 422
        if User.query.filter_by(email=email).first():
            return jsonify(error="Email already registered"), 409
        user = User(email=email, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        return tokens_for(user), 201

    @app.post("/auth/login")
    def login():
        data = request.get_json(silent=True) or {}
        user = User.query.filter_by(email=(data.get("email") or "").lower()).first()
        if not user or not check_password_hash(user.password_hash, data.get("password") or ""):
            return jsonify(error="Invalid email or password"), 401
        return tokens_for(user)

    @app.post("/auth/refresh")
    @jwt_required(refresh=True)
    def refresh():
        return {"access_token": create_access_token(identity=get_jwt_identity())}

    @app.post("/auth/logout")
    @jwt_required(verify_type=False)
    def logout():
        db.session.add(TokenBlocklist(jti=get_jwt()["jti"]))
        db.session.commit()
        return {"message": "Token revoked"}

    @app.get("/auth/me")
    @jwt_required()
    def me():
        user = db.session.get(User, int(get_jwt_identity()))
        if user is None:
            return jsonify(error="User not found"), 404
        return {"id": user.id, "email": user.email}

    @app.cli.command("prune-blocklist")
    def prune_blocklist():
        """Delete blocklist rows older than the longest token lifetime."""
        cutoff = datetime.now(timezone.utc) - app.config["JWT_REFRESH_TOKEN_EXPIRES"]
        n = TokenBlocklist.query.filter(TokenBlocklist.created_at < cutoff).delete()
        db.session.commit()
        print(f"Pruned {n} expired entries")

    with app.app_context():
        db.create_all()
    return app


if __name__ == "__main__":
    create_app().run(debug=True)
