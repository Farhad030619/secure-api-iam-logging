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
