import pytest
from flask import Flask
from flask.testing import FlaskClient
from userm import app, db, User, Session, SessionStatus
import json
import bcrypt
import jwt
import time
import logging
import uuid

logging.basicConfig(level=logging.INFO)

def get_headers(token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client
        with app.app_context():
            db.drop_all()

def generate_unique_session_id():
    return str(uuid.uuid4())

def test_register_existing_user(client: FlaskClient):
    try:
        client.post("/register", json={"username": "testuser", "password": "testpass"})
        response = client.post("/register", json={"username": "testuser", "password": "testpass"})
        assert response.status_code == 400
        assert response.json["message"] == "User already exists!"
    except Exception as e:
        pytest.fail(f"Unexpected error: {e}")

def test_login(client: FlaskClient):
    try:
        test_user = {"username": "testuser", "password": "testpass"}
        client.post("/register", json=test_user)
        response = client.post("/login", json=test_user)
        assert response.status_code == 200
        data = response.get_json()
        assert "token" in data
        assert "expires_at" in data
    except Exception as e:
        pytest.fail(f"Unexpected error: {e}")

def test_invalid_login(client: FlaskClient):
    try:
        response = client.post("/login", json={"username": "wrong", "password": "wrong"})
        assert response.status_code == 401
        assert response.get_json()["message"] == "Invalid credentials!"
    except Exception as e:
        pytest.fail(f"Unexpected error: {e}")

def test_login_max_sessions(client: FlaskClient):
    try:
        client.post("/register", json={"username": "testuser", "password": "testpass"})
        client.post("/login", json={"username": "testuser", "password": "testpass"})
        client.post("/login", json={"username": "testuser", "password": "testpass"})
        response = client.post("/login", json={"username": "testuser", "password": "testpass"})
        assert response.status_code == 403
        assert response.json["message"] == "Too many devices logged in!"
    except Exception as e:
        pytest.fail(f"Unexpected error: {e}")

def test_token_missing(client: FlaskClient):
    try:
        response = client.get("/active_sessions")
        assert response.status_code == 401
        assert response.json["message"] == "Token is missing!"
    except Exception as e:
        pytest.fail(f"Unexpected error: {e}")

def test_token_invalid(client: FlaskClient):
    try:
        headers = {"Authorization": "Bearer invalidtoken"}
        response = client.get("/active_sessions", headers=headers)
        assert response.status_code == 401
        assert response.json["message"] == "Token is invalid!"
    except Exception as e:
        pytest.fail(f"Unexpected error: {e}")

def test_session_expiration(client: FlaskClient):
    try:
        test_user = {"username": "testuser", "password": "testpass"}
        client.post("/register", json=test_user)
        login_response = client.post("/login", json=test_user)
        token = login_response.json["token"]

        with app.app_context():
            user = User.query.filter_by(username=test_user["username"]).first()
            session = Session.query.filter_by(user_id=user.id, status=SessionStatus.ACTIVE).first()
            session.expiry = int(time.time()) - 1
            session.status = SessionStatus.EXPIRED
            db.session.commit()
        
        headers = {"Authorization": f"Bearer {token}"}
        response = client.get("/active_sessions", headers=headers)
        assert response.status_code == 401
        assert response.json["message"] == "Session expired or invalid!"
    except Exception as e:
        pytest.fail(f"Unexpected error: {e}")