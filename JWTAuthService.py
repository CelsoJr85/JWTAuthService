import jwt
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Union
from passlib.context import CryptContext
from functools import wraps
import os


class JWTAuthService:
    def __init__(
            self,
            secret_key: str = None,
            algorithm: str = "HS256",
            access_token_expire_minutes: int = 30,
            refresh_token_expire_days: int = 7
    ):
        self.secret_key = secret_key or self._generate_secret_key()
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def _generate_secret_key(self) -> str:
        return secrets.token_urlsafe(32)

    def hash_password(self, password: str) -> str:
        return self.pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return self.pwd_context.verify(plain_password, hashed_password)

    def create_access_token(
            self,
            data: Dict[str, Any],
            expires_delta: Optional[timedelta] = None
    ) -> str:
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)

        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access"
        })

        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

    def create_refresh_token(self, data: Dict[str, Any]) -> str:
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)

        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "refresh"
        })

        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            return {"error": "Token expirado"}
        except jwt.JWTError:
            return {"error": "Token inválido"}

    def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        payload = self.verify_token(refresh_token)

        if not payload or payload.get("error") or payload.get("type") != "refresh":
            return None

        user_data = {k: v for k, v in payload.items()
                     if k not in ["exp", "iat", "type"]}

        return self.create_access_token(user_data)

    def create_token_pair(self, data: Dict[str, Any]) -> Dict[str, str]:
        return {
            "access_token": self.create_access_token(data),
            "refresh_token": self.create_refresh_token(data),
            "token_type": "bearer"
        }


def jwt_required(auth_service: JWTAuthService):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = None

            try:
                from flask import request
                auth_header = request.headers.get('Authorization')
                if auth_header and auth_header.startswith('Bearer '):
                    token = auth_header.split(' ')[1]
            except ImportError:
                pass

            if not token and 'token' in kwargs:
                token = kwargs.pop('token')

            if not token:
                return {"error": "Token não fornecido"}, 401

            payload = auth_service.verify_token(token)
            if not payload or payload.get("error"):
                return {"error": "Token inválido"}, 401

            kwargs['current_user'] = payload
            return f(*args, **kwargs)

        return decorated_function

    return decorator