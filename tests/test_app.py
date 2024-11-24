import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.models import User
from app.database import SessionLocal, engine
from app.auth import create_access_token, get_user_by_email

client = TestClient(app)

@pytest.fixture(autouse=True)
def session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.rollback()
        db.close()

def test_sign_up(session):
    data = {
        "email": "testuser@example.com",
        "password": "strongpassword123",
    }
    response = client.post("/signup", json=data)
    assert response.status_code == 201
    assert response.json()["email"] == "testuser@example.com"

def test_sign_in(session):
    data = {
        "email": "testuser@example.com",
        "password": "strongpassword123",
    }
    response = client.post("/signin", json=data)
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_valid_token_authentication(session):
    data = {
        "email": "testuser@example.com",
        "password": "strongpassword123",
    }
    client.post("/signup", json=data)

    login_data = {
        "email": "testuser@example.com",
        "password": "strongpassword123",
    }
    response = client.post("/signin", json=login_data)
    access_token = response.json()["access_token"]

    response = client.get("/protected-endpoint", headers={"Authorization": f"Bearer {access_token}"}))
    assert response.status_code == 200

def test_invalid_token_authentication(session):
    response = client.get("/protected-endpoint", headers={"Authorization": "Bearer invalid_token"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid token"

def test_token_revocation(session):
    data = {
        "email": "testuser@example.com",
        "password": "strongpassword123",
    }
    client.post("/signup", json=data)

    login_data = {
        "email": "testuser@example.com",
        "password": "strongpassword123",
    }
    response = client.post("/signin", json=login_data)
    access_token = response.json()["access_token"]

    response = client.post("/revoke-token", json={"access_token": access_token})
    assert response.status_code == 200
    assert response.json()["message"] == "Token revoked"

    response = client.get("/protected-endpoint", headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Token has been revoked"

def test_token_refresh(session):
    data = {
        "email": "testuser@example.com",
        "password": "strongpassword123",
    }
    client.post("/signup", json=data)

    login_data = {
        "email": "testuser@example.com",
        "password": "strongpassword123",
    }
    response = client.post("/signin", json=login_data)
    access_token = response.json()["access_token"]

    response = client.post("/refresh-token", json={"access_token": access_token})
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_invalid_token_refresh(session):
    response = client.post("/refresh-token", json={"access_token": "invalid_token"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid token"
