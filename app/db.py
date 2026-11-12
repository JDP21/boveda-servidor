"""Modelos de la base de datos.

Principio de diseño: la base de datos es NO confiable. Solo almacena material
público (claves públicas) o cifrado del lado del cliente (claves privadas
envueltas, DEK envueltas, archivos cifrados). El servidor nunca puede descifrar.
"""
from datetime import datetime, timezone

from sqlalchemy import (Boolean, DateTime, ForeignKey, Integer, LargeBinary,
                        String, Text, UniqueConstraint, create_engine)
from sqlalchemy.orm import (DeclarativeBase, Mapped, mapped_column,
                            sessionmaker)

from .config import DATABASE_URL


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    # Identificador opaco para WebAuthn (no revela el username)
    webauthn_user_id: Mapped[bytes] = mapped_column(LargeBinary(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Credential(Base):
    """Credencial WebAuthn (passkey). Solo la CLAVE PÚBLICA; la privada vive en el autenticador."""
    __tablename__ = "credentials"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    credential_id: Mapped[bytes] = mapped_column(LargeBinary(1024), unique=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Challenge(Base):
    """Reto WebAuthn de UN SOLO USO (defensa contra replay)."""
    __tablename__ = "challenges"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    challenge: Mapped[bytes] = mapped_column(LargeBinary(64), unique=True)
    purpose: Mapped[str] = mapped_column(String(16))  # "register" | "login"
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class Session(Base):
    """Token de sesión opaco y aleatorio (256 bits)."""
    __tablename__ = "sessions"
    token: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class UserKeys(Base):
    """Claves del usuario generadas en el navegador.

    - enc_public_key / sig_public_key: públicas (RSA-OAEP 3072 / ECDSA P-256), en SPKI base64.
    - wrapped_private_keys: privadas envueltas con AES-256-GCM bajo una KEK = Argon2id(frase).
    - kdf_salt / kdf_params: necesarios para que el cliente re-derive la KEK.
    """
    __tablename__ = "user_keys"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    enc_public_key: Mapped[str] = mapped_column(Text)
    sig_public_key: Mapped[str] = mapped_column(Text)
    wrapped_private_keys: Mapped[str] = mapped_column(Text)
    kdf_salt: Mapped[str] = mapped_column(String(64))
    kdf_params: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class File(Base):
    """Archivo cifrado. `manifest` y `manifest_signature` los produce y firma el cliente."""
    __tablename__ = "files"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # UUID
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    blob_path: Mapped[str] = mapped_column(String(255))
    size: Mapped[int] = mapped_column(Integer)
    manifest: Mapped[str] = mapped_column(Text)            # JSON canónico {id, version, sha256, ...}
    manifest_signature: Mapped[str] = mapped_column(Text)  # firma ECDSA del propietario (base64)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class FileKey(Base):
    """DEK del archivo envuelta con RSA-OAEP para CADA usuario con acceso."""
    __tablename__ = "file_keys"
    __table_args__ = (UniqueConstraint("file_id", "user_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    file_id: Mapped[str] = mapped_column(ForeignKey("files.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    wrapped_dek: Mapped[str] = mapped_column(Text)


class AuditEntry(Base):
    """Log encadenado: h_i = SHA-256(h_{i-1} || evento_i), firmado por el actor."""
    __tablename__ = "audit_log"
    seq: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    event: Mapped[str] = mapped_column(Text)           # JSON canónico del evento
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(Text)       # firma ECDSA del actor sobre entry_hash
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=_connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
