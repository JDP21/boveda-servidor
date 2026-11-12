"""Registro e inicio de sesión EXCLUSIVAMENTE con passkeys (WebAuthn).

Defensas:
- Reto aleatorio de 32 bytes, de un solo uso y con expiración  -> replay.
- expected_origin / expected_rp_id                             -> phishing desde otro dominio.
- Contador de firmas                                           -> autenticador clonado.
"""
import json
import re
import secrets
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession
from webauthn import (generate_authentication_options,
                      generate_registration_options, options_to_json,
                      verify_authentication_response,
                      verify_registration_response)
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria,
                                      PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement,
                                      UserVerificationRequirement)

from ..config import CHALLENGE_TTL_SECONDS, ORIGIN, RP_ID, RP_NAME
from ..db import Challenge, Credential, User, get_db, utcnow
from ..security import new_session

router = APIRouter(prefix="/auth", tags=["auth"])

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")


class UsernameIn(BaseModel):
    username: str


class VerifyIn(BaseModel):
    username: str
    credential: dict  # respuesta JSON de navigator.credentials.create()/get()


def _check_username(username: str) -> str:
    if not USERNAME_RE.match(username):
        raise HTTPException(400, "Usuario inválido (3-32 caracteres: letras, números, _ . -)")
    return username.lower()


def _store_challenge(db: DBSession, username: str, challenge: bytes, purpose: str) -> None:
    db.add(Challenge(username=username, challenge=challenge, purpose=purpose,
                     expires_at=utcnow() + timedelta(seconds=CHALLENGE_TTL_SECONDS)))
    db.commit()


def _consume_challenge(db: DBSession, username: str, credential: dict, purpose: str) -> bytes:
    """Busca el reto que el navegador firmó y lo marca como USADO antes de verificar."""
    try:
        client_data = json.loads(base64url_to_bytes(credential["response"]["clientDataJSON"]))
        challenge = base64url_to_bytes(client_data["challenge"])
    except Exception:
        raise HTTPException(400, "clientDataJSON inválido")
    ch = db.scalar(select(Challenge).where(Challenge.challenge == challenge))
    if (not ch or ch.used or ch.username != username or ch.purpose != purpose
            or ch.expires_at < utcnow()):
        raise HTTPException(400, "Reto inválido, expirado o ya utilizado")
    ch.used = True
    db.commit()
    return challenge


# ---------------------------------------------------------------- Registro
@router.post("/register/options")
def register_options(body: UsernameIn, db: DBSession = Depends(get_db)):
    username = _check_username(body.username)
    if db.scalar(select(User).where(User.username == username)):
        raise HTTPException(409, "El usuario ya existe")
    challenge = secrets.token_bytes(32)
    _store_challenge(db, username, challenge, "register")
    options = generate_registration_options(
        rp_id=RP_ID, rp_name=RP_NAME,
        user_name=username, user_display_name=username,
        user_id=secrets.token_bytes(32),
        challenge=challenge,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED),
        supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256,
                                COSEAlgorithmIdentifier.EDDSA],
    )
    return json.loads(options_to_json(options))


@router.post("/register/verify")
def register_verify(body: VerifyIn, db: DBSession = Depends(get_db)):
    username = _check_username(body.username)
    if db.scalar(select(User).where(User.username == username)):
        raise HTTPException(409, "El usuario ya existe")
    challenge = _consume_challenge(db, username, body.credential, "register")
    try:
        verified = verify_registration_response(
            credential=body.credential, expected_challenge=challenge,
            expected_rp_id=RP_ID, expected_origin=ORIGIN)
    except Exception as e:
        raise HTTPException(400, f"Registro WebAuthn rechazado: {e}")

    user = User(username=username, webauthn_user_id=secrets.token_bytes(32))
    db.add(user)
    db.flush()
    db.add(Credential(user_id=user.id, credential_id=verified.credential_id,
                      public_key=verified.credential_public_key,
                      sign_count=verified.sign_count))
    db.commit()
    return {"ok": True, "username": username, "token": new_session(db, user)}


# ---------------------------------------------------------------- Login
@router.post("/login/options")
def login_options(body: UsernameIn, db: DBSession = Depends(get_db)):
    username = _check_username(body.username)
    user = db.scalar(select(User).where(User.username == username))
    if not user:
        raise HTTPException(404, "Usuario no encontrado")
    creds = db.scalars(select(Credential).where(Credential.user_id == user.id)).all()
    challenge = secrets.token_bytes(32)
    _store_challenge(db, username, challenge, "login")
    options = generate_authentication_options(
        rp_id=RP_ID, challenge=challenge,
        allow_credentials=[PublicKeyCredentialDescriptor(id=c.credential_id) for c in creds],
        user_verification=UserVerificationRequirement.PREFERRED)
    return json.loads(options_to_json(options))


@router.post("/login/verify")
def login_verify(body: VerifyIn, db: DBSession = Depends(get_db)):
    username = _check_username(body.username)
    user = db.scalar(select(User).where(User.username == username))
    if not user:
        raise HTTPException(404, "Usuario no encontrado")
    challenge = _consume_challenge(db, username, body.credential, "login")
    try:
        cred_id = base64url_to_bytes(body.credential["rawId"])
    except Exception:
        raise HTTPException(400, "rawId inválido")
    cred = db.scalar(select(Credential).where(Credential.credential_id == cred_id,
                                              Credential.user_id == user.id))
    if not cred:
        raise HTTPException(400, "Credencial desconocida")
    try:
        verified = verify_authentication_response(
            credential=body.credential, expected_challenge=challenge,
            expected_rp_id=RP_ID, expected_origin=ORIGIN,
            credential_public_key=cred.public_key,
            credential_current_sign_count=cred.sign_count)
    except Exception as e:
        raise HTTPException(401, f"Autenticación WebAuthn rechazada: {e}")
    cred.sign_count = verified.new_sign_count
    db.commit()
    return {"ok": True, "username": username, "token": new_session(db, user)}
