"""Directorio de claves públicas + respaldo de claves privadas ENVUELTAS.

El servidor nunca recibe claves privadas en claro: el cliente las envuelve con
AES-256-GCM usando una KEK derivada con Argon2id de la frase de recuperación.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession

from ..db import User, UserKeys, get_db
from ..security import current_user

router = APIRouter(prefix="/keys", tags=["keys"])


class KeysIn(BaseModel):
    enc_public_key: str = Field(..., description="RSA-OAEP 3072, SPKI base64")
    sig_public_key: str = Field(..., description="ECDSA P-256, SPKI base64")
    wrapped_private_keys: str = Field(..., description="JSON {iv, ct} AES-GCM, base64")
    kdf_salt: str
    kdf_params: str = Field(..., description='p.ej. {"alg":"argon2id","m":65536,"t":3,"p":1}')


@router.put("/me")
def put_my_keys(body: KeysIn, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    keys = db.get(UserKeys, user.id)
    if keys:
        # Un cambio de claves de identidad debe ser visible para los demás (alerta de huella)
        for k, v in body.model_dump().items():
            setattr(keys, k, v)
    else:
        db.add(UserKeys(user_id=user.id, **body.model_dump()))
    db.commit()
    return {"ok": True}


@router.get("/me")
def get_my_keys(user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    keys = db.get(UserKeys, user.id)
    if not keys:
        raise HTTPException(404, "Aún no has generado tus claves")
    return {"username": user.username, "enc_public_key": keys.enc_public_key,
            "sig_public_key": keys.sig_public_key,
            "wrapped_private_keys": keys.wrapped_private_keys,
            "kdf_salt": keys.kdf_salt, "kdf_params": keys.kdf_params}


@router.get("/{username}")
def get_public_keys(username: str, _: User = Depends(current_user), db: DBSession = Depends(get_db)):
    """Devuelve SOLO las claves públicas. El cliente DEBE verificar la huella antes de usarlas."""
    other = db.scalar(select(User).where(User.username == username.lower()))
    keys = db.get(UserKeys, other.id) if other else None
    if not keys:
        raise HTTPException(404, "Usuario o claves no encontrados")
    return {"username": other.username, "enc_public_key": keys.enc_public_key,
            "sig_public_key": keys.sig_public_key}
