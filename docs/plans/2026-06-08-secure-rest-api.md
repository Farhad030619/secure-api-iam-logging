# Secure REST API Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create a minimalist but extremely secure REST API in Python (FastAPI) featuring JWT authentication, Role-Based Access Control (RBAC), security audit logging (failed logins & unauthorized access), rate limiting, and secure HTTP headers.

**Architecture:** The project will be structured cleanly in a single folder. We will use a mock thread-safe in-memory database to store hashed passwords and user roles. Standard FastAPI dependencies will enforce JWT verification and RBAC roles, while security audit logs will be written to a dedicated `logs/audit.log` file using Python's logging system. Rate limiting will protect the login endpoint from brute-force attacks.

**Tech Stack:** Python 3.12+, FastAPI, Uvicorn, Pydantic (v2) & Pydantic Settings, PyJWT (or python-jose), Bcrypt (directly for password hashing to avoid deprecated passlib warnings), SlowAPI (rate limiting), Pytest & HTTPX (for testing).

---

### Task 1: Project Setup and Requirements

**Files:**
- Create: `requirements.txt`
- Create: `.env`

**Step 1: Write requirements.txt**
Create the `requirements.txt` file listing all required dependencies.

```text
fastapi>=0.110.0
uvicorn>=0.28.0
pydantic[email]>=2.6.0
pydantic-settings>=2.2.0
python-jose[cryptography]>=3.3.0
bcrypt>=4.1.0
slowapi>=0.1.9
python-multipart>=0.0.9
pytest>=8.0.0
httpx>=0.27.0
```

**Step 2: Write default .env file**
Create a `.env` file containing the default configuration values.

```env
APP_NAME="Secure-REST-API"
DEBUG=false
SECRET_KEY="super-secret-development-key-that-should-be-changed-in-production"
ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES=15
RATE_LIMIT_LOGIN="5/minute"
```

**Step 3: Verify installation command**
Run standard install in a virtual environment.
Run: `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
Expected: Packages install successfully.

---

### Task 2: Configuration Module

**Files:**
- Create: `app/config.py`

**Step 1: Create configuration test**
Wait, we will verify the config works by importing it.
Let's write `app/config.py` using Pydantic Settings.

```python
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )
    
    APP_NAME: str = "Secure-REST-API"
    DEBUG: bool = False
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    RATE_LIMIT_LOGIN: str = "5/minute"

settings = Settings()
```

**Step 2: Verify config import**
Run: `python3 -c "from app.config import settings; print(settings.APP_NAME)"`
Expected: Prints `Secure-REST-API`.

---

### Task 3: Security Audit Logger

**Files:**
- Create: `app/logger.py`
- Create: `logs/.gitkeep`

**Step 1: Write app/logger.py**
Create the logging module that configures a standard logger and a dedicated security audit logger. The audit logger will write to `logs/audit.log` with a custom formatter.

```python
import os
import logging
from logging.handlers import RotatingFileHandler

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)

# Define audit log formatter
audit_formatter = logging.Formatter(
    '[%(asctime)s] SECURITY_AUDIT | IP: %(client_ip)s | User: %(username)s | Event: %(event_type)s | %(message)s'
)

# Set up audit log handler (rotating log file, 10MB limit, keep 5 backups)
audit_handler = RotatingFileHandler(
    filename=os.path.join("logs", "audit.log"),
    maxBytes=10 * 1024 * 1024,
    backupCount=5,
    encoding="utf-8"
)
audit_handler.setFormatter(audit_formatter)

# Create and configure the audit logger
audit_logger = logging.getLogger("security_audit")
audit_logger.setLevel(logging.INFO)
audit_logger.addHandler(audit_handler)
# Prevent audit logs from propagating to the root logger (console) if we want it isolated
audit_logger.propagate = False

def log_security_event(event_type: str, username: str, client_ip: str, details: str):
    """
    Helper function to log a security audit event.
    Common event types:
    - LOGIN_SUCCESS
    - FAILED_LOGIN_ATTEMPT
    - UNAUTHORIZED_ADMIN_ACCESS
    - REGISTER_SUCCESS
    """
    audit_logger.info(
        details,
        extra={
            "client_ip": client_ip,
            "username": username,
            "event_type": event_type
        }
    )
```

**Step 2: Verify audit logging**
Run a test script to check if audit.log is created and correctly formatted.
Run: `python3 -c "from app.logger import log_security_event; log_security_event('TEST_EVENT', 'test_user', '127.0.0.1', 'Test security message')" && cat logs/audit.log`
Expected: Output matches format: `[2026-06-08 ...] SECURITY_AUDIT | IP: 127.0.0.1 | User: test_user | Event: TEST_EVENT | Test security message`

---

### Task 4: In-Memory Database

**Files:**
- Create: `app/database.py`

**Step 1: Write app/database.py**
Create a thread-safe, in-memory user database. It will contain helper functions to retrieve, save, and check user presence.

```python
import threading
from typing import Dict, Optional
from pydantic import BaseModel

class UserDBModel(BaseModel):
    username: str
    hashed_password: str
    role: str  # "User" or "Admin"
    is_active: bool = True

class InMemoryDatabase:
    def __init__(self):
        # Dictionary format: {username: UserDBModel}
        self._users: Dict[str, UserDBModel] = {}
        self._lock = threading.Lock()

    def get_user(self, username: str) -> Optional[UserDBModel]:
        with self._lock:
            return self._users.get(username.lower())

    def save_user(self, user: UserDBModel) -> bool:
        with self._lock:
            username_lower = user.username.lower()
            if username_lower in self._users:
                return False  # User already exists
            self._users[username_lower] = user
            return True

# Singleton database instance
db = InMemoryDatabase()
```

---

### Task 5: Schemas (Pydantic Models)

**Files:**
- Create: `app/schemas.py`

**Step 1: Write app/schemas.py**
Create the input and output validation schemas.

```python
from pydantic import BaseModel, Field, field_validator
import re
from typing import Optional

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Username between 3 and 50 characters")
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters long")
    role: str = Field(default="User", description="User role, either 'User' or 'Admin'")

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        # Prevent any special character injection in username (alphanumeric and underscores only)
        if not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError("Username must be alphanumeric and can only contain letters, numbers, and underscores")
        return v

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in ("User", "Admin"):
            raise ValueError("Role must be either 'User' or 'Admin'")
        return v

class UserResponse(BaseModel):
    username: str
    role: str
    is_active: bool

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None
```

---

### Task 6: Authentication & Authorization Core

**Files:**
- Create: `app/auth.py`

**Step 1: Write app/auth.py**
Implement security helpers for password hashing (using Bcrypt directly), token creation, and FastAPI security dependencies to fetch current user and enforce RBAC.

```python
import bcrypt
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from app.config import settings
from app.database import db, UserDBModel
from app.schemas import TokenData

# OAuth2 scheme for token retrieval
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")

def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against its bcrypt hash."""
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a secure JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserDBModel:
    """FastAPI Dependency to get and validate the current user from the JWT."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role is None:
            raise credentials_exception
        token_data = TokenData(username=username, role=role)
    except JWTError:
        raise credentials_exception
        
    user = db.get_user(token_data.username)
    if user is None:
        raise credentials_exception
    return user

class RoleChecker:
    """Dependency to check if the current user has the required role."""
    def __init__(self, allowed_roles: list[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, current_user: UserDBModel = Depends(get_current_user)) -> UserDBModel:
        if current_user.role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: You do not have permission to access this resource"
            )
        return current_user
```

---

### Task 7: Main FastAPI Application & Security Middlewares

**Files:**
- Create: `app/main.py`

**Step 1: Write app/main.py**
Assemble the FastAPI app. Implement custom middlewares to inject secure HTTP headers (equivalent to Helmet), set up CORS, configure the SlowAPI rate limiter, and define the endpoints (register, login, user dashboard, admin dashboard). Ensure unauthorized admin access and failed login attempts are logged via `log_security_event`.

```python
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
import time

from app.config import settings
from app.database import db, UserDBModel
from app.schemas import UserRegister, UserResponse, Token
from app.auth import hash_password, verify_password, create_access_token, get_current_user, RoleChecker
from app.logger import log_security_event

# Initialize SlowAPI rate limiter
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title=settings.APP_NAME, debug=settings.DEBUG)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# 1. CORS Middleware (Restrict as needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change to specific domains in production
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# 2. Custom Security Headers Middleware (Helmet equivalent)
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    # HSTS (HTTP Strict Transport Security) - Force HTTPS
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    # XSS Protection (older browsers, but good fallback)
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # Content Security Policy (restrict sources)
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
    # Referrer Policy
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

# Helper to get client IP reliably
def get_client_ip(request: Request) -> str:
    # Handle proxy headers if deployed behind reverse proxy
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

# --- Endpoints ---

@app.post("/api/v1/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_in: UserRegister, request: Request):
    client_ip = get_client_ip(request)
    
    # Check if user already exists
    if db.get_user(user_in.username) is not None:
        log_security_event(
            event_type="REGISTER_FAILED",
            username=user_in.username,
            client_ip=client_ip,
            details=f"Registration failed: username '{user_in.username}' already exists."
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # Create new user
    hashed = hash_password(user_in.password)
    new_user = UserDBModel(
        username=user_in.username,
        hashed_password=hashed,
        role=user_in.role
    )
    db.save_user(new_user)
    
    log_security_event(
        event_type="REGISTER_SUCCESS",
        username=user_in.username,
        client_ip=client_ip,
        details=f"User registered successfully with role '{user_in.role}'."
    )
    
    return UserResponse(
        username=new_user.username,
        role=new_user.role,
        is_active=new_user.is_active
    )

@app.post("/api/v1/auth/login", response_model=Token)
@limiter.limit(settings.RATE_LIMIT_LOGIN)
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    client_ip = get_client_ip(request)
    username = form_data.username
    password = form_data.password
    
    user = db.get_user(username)
    if not user or not verify_password(password, user.hashed_password):
        # AUDIT LOG: Failed login attempt
        log_security_event(
            event_type="FAILED_LOGIN_ATTEMPT",
            username=username,
            client_ip=client_ip,
            details="Failed login attempt: invalid credentials."
        )
        # Add a tiny delay to mitigate timing attacks
        time.sleep(0.1)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        log_security_event(
            event_type="FAILED_LOGIN_ATTEMPT",
            username=username,
            client_ip=client_ip,
            details="Failed login attempt: account is inactive."
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user account"
        )
        
    # AUDIT LOG: Successful login
    log_security_event(
        event_type="LOGIN_SUCCESS",
        username=username,
        client_ip=client_ip,
        details="User logged in successfully."
    )
    
    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    return Token(access_token=access_token, token_type="bearer")

# Enforce User/Admin authorization for general dashboard
@app.get("/api/v1/dashboard", response_model=UserResponse)
async def get_dashboard(current_user: UserDBModel = Depends(RoleChecker(["User", "Admin"]))):
    return UserResponse(
        username=current_user.username,
        role=current_user.role,
        is_active=current_user.is_active
    )

# Enforce Admin role ONLY
@app.get("/api/v1/admin", response_model=UserResponse)
async def get_admin_dashboard(request: Request, current_user: UserDBModel = Depends(get_current_user)):
    client_ip = get_client_ip(request)
    
    # Check role
    if current_user.role != "Admin":
        # AUDIT LOG: Unauthorized access attempt to admin panel
        log_security_event(
            event_type="UNAUTHORIZED_ADMIN_ACCESS",
            username=current_user.username,
            client_ip=client_ip,
            details="Access denied: user attempted to access admin panel without required privileges."
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Admins only"
        )
        
    return UserResponse(
        username=current_user.username,
        role=current_user.role,
        is_active=current_user.is_active
    )
```

---

### Task 8: Automated Security Testing Suite

**Files:**
- Create: `tests/test_api.py`

**Step 1: Write tests/test_api.py**
Create tests using pytest and FastAPI's test framework. Tests should cover:
1. Registration validation (username patterns, password requirements).
2. Login with correct and incorrect credentials (verifying audit log writing for failed login).
3. Accessing `/dashboard` with and without a JWT.
4. Accessing `/admin` as a `User` (verifying 403 Forbidden and audit log writing) vs `Admin` (verifying 200 OK).
5. Verification that security headers (HSTS, nosniff, etc.) are present on all responses.
6. Rate limiting on `/login`.

```python
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
    assert "Too Many Requests" in response.json()["error"]
```

**Step 2: Run verification test**
Run: `pytest tests/test_api.py -v`
Expected: All tests pass.

---

### Task 9: Portfolio Documentation (README.md)

**Files:**
- Create: `README.md`

**Step 1: Write README.md**
Document the project in English, explaining the security architecture, how JWT and RBAC are enforced, the security audit logging design, rate limiting, and HTTP security headers. Provide setup and testing instructions.

---

## Execution Handoff

Plan complete and saved to `docs/plans/2026-06-08-secure-rest-api.md`. Two execution options:

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration.

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints.

Which approach?
