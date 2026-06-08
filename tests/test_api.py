import pytest
from fastapi.testclient import TestClient
import os
import shutil

# Make sure we use a temporary secret key for tests
os.environ["SECRET_KEY"] = "test-secret-key-test-secret-key-test-secret-key"

from app.main import app
from app.database import db, UserDBModel
from app.auth import hash_password

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_database_and_logs():
    # Reset DB users dictionary
    db._users.clear()
    
    # Clear audit.log if it exists
    audit_file = os.path.join("logs", "audit.log")
    if os.path.exists(audit_file):
        # Open and truncate the file
        with open(audit_file, "w") as f:
            f.truncate(0)
    yield

def test_security_headers():
    response = client.get("/api/v1/dashboard")
    assert response.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Content-Security-Policy"] == "default-src 'self'; frame-ancestors 'none';"
    assert response.headers["Referrer-Policy"] == "no-referrer"

def test_user_registration():
    # Successful User registration
    response = client.post(
        "/api/v1/auth/register",
        json={"username": "alice", "password": "securepassword123", "role": "User"}
    )
    assert response.status_code == 201
    assert response.json()["username"] == "alice"
    assert response.json()["role"] == "User"

    # Duplicate username
    response = client.post(
        "/api/v1/auth/register",
        json={"username": "alice", "password": "anotherpassword123", "role": "User"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Username already registered"

    # Invalid characters in username
    response = client.post(
        "/api/v1/auth/register",
        json={"username": "user@name!", "password": "securepassword123", "role": "User"}
    )
    assert response.status_code == 422

    # Password too short
    response = client.post(
        "/api/v1/auth/register",
        json={"username": "charlie", "password": "123", "role": "User"}
    )
    assert response.status_code == 422

    # Invalid role
    response = client.post(
        "/api/v1/auth/register",
        json={"username": "charlie", "password": "securepassword123", "role": "SuperAdmin"}
    )
    assert response.status_code == 422

def test_login_and_audit_logging():
    # Register a user
    client.post(
        "/api/v1/auth/register",
        json={"username": "bob", "password": "bobpassword123", "role": "User"}
    )
    
    # Successful login
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "bob", "password": "bobpassword123"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"

    # Failed login
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "bob", "password": "wrongpassword"}
    )
    assert response.status_code == 401
    
    # Check audit log contains the failure
    audit_file = os.path.join("logs", "audit.log")
    assert os.path.exists(audit_file)
    with open(audit_file, "r") as f:
        log_content = f.read()
    assert "FAILED_LOGIN_ATTEMPT" in log_content
    assert "bob" in log_content
    assert "Failed login attempt: invalid credentials." in log_content

def test_rbac_user_vs_admin():
    # Register normal User and Admin
    client.post(
        "/api/v1/auth/register",
        json={"username": "normal_user", "password": "userpass123", "role": "User"}
    )
    client.post(
        "/api/v1/auth/register",
        json={"username": "admin_user", "password": "adminpass123", "role": "Admin"}
    )

    # Get tokens
    user_token = client.post("/api/v1/auth/login", data={"username": "normal_user", "password": "userpass123"}).json()["access_token"]
    admin_token = client.post("/api/v1/auth/login", data={"username": "admin_user", "password": "adminpass123"}).json()["access_token"]

    # 1. Access dashboard (both should be allowed)
    resp1 = client.get("/api/v1/dashboard", headers={"Authorization": f"Bearer {user_token}"})
    assert resp1.status_code == 200
    assert resp1.json()["username"] == "normal_user"

    resp2 = client.get("/api/v1/dashboard", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp2.status_code == 200
    assert resp2.json()["username"] == "admin_user"

    # 2. Access Admin endpoint as User (Should be Forbidden 403 & audited)
    resp3 = client.get("/api/v1/admin", headers={"Authorization": f"Bearer {user_token}"})
    assert resp3.status_code == 403
    
    # Verify audit log contains unauthorized admin access
    audit_file = os.path.join("logs", "audit.log")
    with open(audit_file, "r") as f:
        log_content = f.read()
    assert "UNAUTHORIZED_ADMIN_ACCESS" in log_content
    assert "normal_user" in log_content

    # 3. Access Admin endpoint as Admin (Should be Allowed 200)
    resp4 = client.get("/api/v1/admin", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp4.status_code == 200
    assert resp4.json()["username"] == "admin_user"

def test_rate_limiting():
    # Login endpoint has rate limit, let's trigger it.
    # Note: in TestClient, the key is the mock client remote address.
    # Let's perform multiple login requests quickly.
    # Limit is 5/minute. Request 6 times.
    for i in range(6):
        response = client.post(
            "/api/v1/auth/login",
            data={"username": "does_not_matter", "password": "does_not_matter"}
        )
        if response.status_code == 429:
            break
            
    assert response.status_code == 429
    assert "Rate limit exceeded" in response.json()["error"]
