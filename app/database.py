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
