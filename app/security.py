"""Sesiones y utilidades de seguridad del servidor."""
import base64
import secrets
from datetime import timedelta

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session as DBSession

from .config import SESSION_TTL_MINUTES
from .db import Session, User, get_db, utcnow


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(data: str) -> bytes:
    return base64.b64decode(data)


def new_session(db: DBSession, user: User) -> str:
    token = secrets.token_hex(32)  # 256 bits, CSPRNG
    db.add(Session(token=token, user_id=user.id,
                   expires_at=utcnow() + timedelta(minutes=SESSION_TTL_MINUTES)))
    db.commit()
    return token


def current_user(authorization: str = Header(default=""),
                 db: DBSession = Depends(get_db)) -> User:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Falta token de sesión")
    token = authorization.removeprefix("Bearer ").strip()
    sess = db.get(Session, token)
    if not sess or sess.expires_at < utcnow():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sesión inválida o expirada")
    user = db.get(User, sess.user_id)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Usuario no existe")
    return user
