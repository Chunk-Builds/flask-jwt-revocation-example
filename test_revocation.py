import pytest
from app import create_app, db


@pytest.fixture
def client():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "JWT_SECRET_KEY": "test-secret-key-that-is-at-least-32-bytes",
    })
    with app.app_context():
        yield app.test_client()
        db.session.remove()
        db.drop_all()


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_logout_revokes_access_token(client):
    tokens = client.post("/auth/register", json={
        "email": "alice@example.com", "password": "supersecret",
    }).get_json()
    h = bearer(tokens["access_token"])

    assert client.get("/auth/me", headers=h).status_code == 200
    assert client.post("/auth/logout", headers=h).status_code == 200

    r = client.get("/auth/me", headers=h)
    assert r.status_code == 401
    assert "revoked" in r.get_json()["error"]


def test_logout_revokes_refresh_token(client):
    tokens = client.post("/auth/register", json={
        "email": "bob@example.com", "password": "supersecret",
    }).get_json()
    h = bearer(tokens["refresh_token"])

    assert client.post("/auth/logout", headers=h).status_code == 200
    assert client.post("/auth/refresh", headers=h).status_code == 401


def test_refresh_rejects_access_token(client):
    tokens = client.post("/auth/register", json={
        "email": "carol@example.com", "password": "supersecret",
    }).get_json()
    assert client.post("/auth/refresh", headers=bearer(tokens["access_token"])).status_code == 401
