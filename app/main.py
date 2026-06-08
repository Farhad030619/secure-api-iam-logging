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
    if request.url.path in ("/docs", "/redoc", "/openapi.json"):
        # Allow Swagger UI CDN resources
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com; "
            "frame-ancestors 'none';"
        )
    else:
        # Ultra strict policy for the REST API endpoints
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
    # Referrer Policy
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

from fastapi.responses import RedirectResponse

# Helper to get client IP reliably
def get_client_ip(request: Request) -> str:
    # Handle proxy headers if deployed behind reverse proxy
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

# --- Endpoints ---

@app.get("/")
async def root_redirect():
    return RedirectResponse(url="/docs")


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
