# Minimalist & Secure REST API (FastAPI)

A minimalist, high-performance, and extremely secure REST API built with **Python (FastAPI)**. This project demonstrates backend security best practices, Identity & Access Management (IAM), role-based authorization, security audit logging, and protection against common web vulnerabilities.

This API is designed as a secure control plane or administrative backend, making it an excellent complement to security automation and monitoring tools (such as PCAP parsers and Intrusion Detection Systems).

---

## 🔒 Security Features Implemented

### 1. Authentication (AuthN)
- **User Registration**: Enforces strict Pydantic inputs (alphanumeric usernames, password complexity of min-length 8).
- **Secure Password Hashing**: Uses modern `bcrypt` hashing with salt rounds (work factor) of 12. Hashing is performed directly to avoid deprecated python-jose/passlib compatibility warnings.
- **JWT (JSON Web Tokens) Session Management**: Issues secure, short-lived (15 minutes) access tokens upon successful login using `OAuth2PasswordBearer`.

### 2. Authorization (AuthZ) & RBAC
- **Role-Based Access Control (RBAC)**: Implements two user tiers: `User` and `Admin`.
- **FastAPI Dependencies**: Restricts routes dynamically.
  - `/api/v1/dashboard`: Accessible to both `User` and `Admin`.
  - `/api/v1/admin`: Accessible **only** to `Admin`. Attempts to access this route by non-admins result in immediate access rejection (`403 Forbidden`) and security audit logging.

### 3. Security Audit Logging
- Isolation of security events into a dedicated log file: `logs/audit.log`.
- **Log Rotation**: Automatic rotation with `RotatingFileHandler` (max size 10MB, up to 5 backups) to prevent log-injection storage denial-of-service.
- **Audited Events**:
  - `REGISTER_SUCCESS` / `REGISTER_FAILED`
  - `LOGIN_SUCCESS` / `FAILED_LOGIN_ATTEMPT` (logs target username and source IP)
  - `UNAUTHORIZED_ADMIN_ACCESS` (logs offender username, target path, and source IP)
- **Structured format**:
  `[TIMESTAMP] SECURITY_AUDIT | IP: <client_ip> | User: <username> | Event: <event_type> | <detailed_message>`

### 4. HTTP Security Headers (Helmet Equivalent)
A custom ASGI middleware injects secure-by-default HTTP headers to prevent client-side attacks:
- **HTTP Strict Transport Security (HSTS)**: `Strict-Transport-Security: max-age=31536000; includeSubDomains` (forces HTTPS).
- **MIME Sniffing Prevention**: `X-Content-Type-Options: nosniff`.
- **Clickjacking Protection**: `X-Frame-Options: DENY`.
- **XSS Mitigation**: `X-XSS-Protection: 1; mode=block`.
- **Content Security Policy (CSP)**: Restricts script/frame execution (`default-src 'self'; frame-ancestors 'none';`).
- **Referrer Policy**: `Referrer-Policy: no-referrer`.

### 5. Rate Limiting (Brute-Force Protection)
- Implements `slowapi` (a FastAPI extension of `limits`) on the `/api/v1/auth/login` endpoint.
- Protects against brute-force credential stuffing by restricting login requests (default: `5 attempts per minute` per client IP).
- Returns a standard `429 Too Many Requests` status code when the limit is exceeded.

---

## 🛠️ Tech Stack
- **Framework**: FastAPI (Asynchronous Python ASGI)
- **Settings & Validation**: Pydantic v2 & Pydantic Settings
- **Cryptographic Operations**: Bcrypt, PyJWT (python-jose)
- **Rate Limiting**: SlowAPI / Limits
- **Testing**: Pytest & HTTPX (TestClient)

---

## 📂 Project Structure
```text
.
├── app/
│   ├── __init__.py
│   ├── main.py          # FastAPI App, Middlewares, and Endpoints
│   ├── config.py        # Settings configuration (Pydantic Settings)
│   ├── auth.py          # Hashing, JWT logic, and RBAC dependencies
│   ├── database.py      # Thread-safe in-memory User Database (singleton)
│   ├── schemas.py       # Pydantic input/output request schemas
│   └── logger.py        # Audit Logging settings
├── logs/
│   └── audit.log        # Target file for security events
├── tests/
│   └── test_api.py      # Automated security verification tests
├── .env                 # Environment secrets
├── requirements.txt     # Python dependencies
└── README.md            # Documentation
```

---

## 🚀 Setup & Installation

### 1. Prerequisites
- Python 3.12+ (Works on modern Python 3.14 as verified by test environments)

### 2. Installation
Clone this repository to your local directory:
```bash
# Create a virtual environment
python3 -m venv .venv

# Activate the virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the Server
Start the development server using Uvicorn:
```bash
PYTHONPATH=. uvicorn app.main:app --reload
```
The server will start at `http://127.0.0.1:8000`. 
FastAPI automatically generates interactive Swagger API documentation at `http://127.0.0.1:8000/docs`.

---

## 🧪 Testing Suite
An automated suite of 5 integration tests is provided to verify all security aspects:
1. **Security Headers Verification**: Checks that all responses contain security-hardening headers.
2. **Registration Constraints**: Validates username character filters, password length constraints, and role rules.
3. **Audit Log Generation**: Asserts that failed logins trigger audit entries in `logs/audit.log` containing correct IPs, usernames, and event descriptions.
4. **RBAC Policy Enforcement**: Verifies that Admins can access `/admin` but normal Users are rejected with a `403 Forbidden` and audited.
5. **Rate Limiter Action**: Simulates a brute force attack on the login route to verify that IP-based rate limiting throws a `429` status code.

Run the tests:
```bash
PYTHONPATH=. .venv/bin/pytest tests/test_api.py -v
```

---

## 📈 Audit Log Sample
When security violations occur, they are recorded in `logs/audit.log`. A sample output is:
```text
[2026-06-08 20:51:11,102] SECURITY_AUDIT | IP: 127.0.0.1 | User: normal_user | Event: UNAUTHORIZED_ADMIN_ACCESS | Access denied: user attempted to access admin panel without required privileges.
[2026-06-08 20:51:12,234] SECURITY_AUDIT | IP: 127.0.0.1 | User: bob | Event: FAILED_LOGIN_ATTEMPT | Failed login attempt: invalid credentials.
```
