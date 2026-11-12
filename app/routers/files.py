"""Archivos cifrados (cifrado de sobre).

El cliente envía: el archivo YA cifrado con AES-256-GCM, la DEK envuelta con su
clave pública RSA-OAEP y un manifiesto firmado {id, version, sha256, ...}.
El servidor solo almacena y controla acceso; la verificación de firma y hash la
hace siempre el cliente al descargar (no confía en el servidor).
"""
import json
import os
import uuid

from fastapi import (APIRouter, Depends, File as FileParam, Form,
                     HTTPException, UploadFile)
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession

from ..config import BLOB_DIR, MAX_FILE_BYTES
from ..db import File, FileKey, User, get_db
from ..security import current_user

router = APIRouter(prefix="/files", tags=["files"])


def _blob_path(file_id: str, version: int) -> str:
    os.makedirs(BLOB_DIR, exist_ok=True)
    return os.path.join(BLOB_DIR, f"{file_id}.v{version}.bin")


def _check_manifest(manifest: str, file_id: str, version: int) -> None:
    """Coherencia mínima. La garantía real es la firma, que verifica el cliente."""
    try:
        m = json.loads(manifest)
    except ValueError:
        raise HTTPException(400, "Manifiesto no es JSON válido")
    if m.get("id") != file_id or m.get("version") != version:
        raise HTTPException(400, "El manifiesto no coincide con id/versión")


async def _save_blob(upload: UploadFile, path: str) -> int:
    data = await upload.read()
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(413, "Archivo demasiado grande")
    with open(path, "wb") as f:
        f.write(data)
    return len(data)


def _get_accessible(db: DBSession, file_id: str, user: User) -> tuple[File, FileKey]:
    f = db.get(File, file_id)
    fk = db.scalar(select(FileKey).where(FileKey.file_id == file_id, FileKey.user_id == user.id)) if f else None
    if not f or not fk:
        raise HTTPException(404, "Archivo no encontrado")
    return f, fk


def _owned(db: DBSession, file_id: str, user: User) -> File:
    f = db.get(File, file_id)
    if not f or f.owner_id != user.id:
        raise HTTPException(404, "Archivo no encontrado")
    return f


@router.post("/new-id")
def new_file_id(_: User = Depends(current_user)):
    """El cliente pide un id para incluirlo en el manifiesto y en los datos asociados de GCM."""
    return {"id": str(uuid.uuid4())}


@router.post("")
async def upload(file_id: str = Form(...), version: int = Form(1),
                 wrapped_dek: str = Form(...), manifest: str = Form(...),
                 manifest_signature: str = Form(...),
                 blob: UploadFile = FileParam(...),
                 user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    try:
        uuid.UUID(file_id)
    except ValueError:
        raise HTTPException(400, "id inválido")
    if db.get(File, file_id):
        raise HTTPException(409, "Ya existe; usa PUT /files/{id} para una nueva versión")
    _check_manifest(manifest, file_id, version)
    path = _blob_path(file_id, version)
    size = await _save_blob(blob, path)
    db.add(File(id=file_id, owner_id=user.id, version=version, blob_path=path, size=size,
                manifest=manifest, manifest_signature=manifest_signature))
    db.add(FileKey(file_id=file_id, user_id=user.id, wrapped_dek=wrapped_dek))
    db.commit()
    return {"ok": True, "id": file_id, "version": version}


class ReencryptKey(BaseModel):
    username: str
    wrapped_dek: str


@router.put("/{file_id}")
async def new_version(file_id: str, version: int = Form(...),
                      manifest: str = Form(...), manifest_signature: str = Form(...),
                      wrapped_deks: str = Form(..., description='JSON [{"username","wrapped_dek"}]'),
                      blob: UploadFile = FileParam(...),
                      user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    """Nueva versión (o re-cifrado tras revocar) con DEK NUEVA para los usuarios que conservan acceso."""
    f = _owned(db, file_id, user)
    if version <= f.version:
        raise HTTPException(409, "La versión debe ser mayor que la actual (anti-rollback)")
    _check_manifest(manifest, file_id, version)
    try:
        keys = [ReencryptKey(**k) for k in json.loads(wrapped_deks)]
    except Exception:
        raise HTTPException(400, "wrapped_deks inválido")
    path = _blob_path(file_id, version)
    size = await _save_blob(blob, path)
    old_path = f.blob_path
    f.version, f.blob_path, f.size = version, path, size
    f.manifest, f.manifest_signature = manifest, manifest_signature
    db.query(FileKey).filter(FileKey.file_id == file_id).delete()
    for k in keys:
        u = db.scalar(select(User).where(User.username == k.username.lower()))
        if u:
            db.add(FileKey(file_id=file_id, user_id=u.id, wrapped_dek=k.wrapped_dek))
    db.commit()
    if old_path != path and os.path.exists(old_path):
        os.remove(old_path)
    return {"ok": True, "version": version}


@router.get("")
def list_files(user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    rows = db.execute(select(File, User.username).join(FileKey, FileKey.file_id == File.id)
                      .join(User, User.id == File.owner_id)
                      .where(FileKey.user_id == user.id)).all()
    return [{"id": f.id, "owner": owner, "version": f.version, "size": f.size,
             "manifest": f.manifest, "updated_at": f.updated_at.isoformat()} for f, owner in rows]


@router.get("/{file_id}/meta")
def file_meta(file_id: str, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    f, fk = _get_accessible(db, file_id, user)
    owner = db.get(User, f.owner_id)
    return {"id": f.id, "owner": owner.username, "version": f.version,
            "manifest": f.manifest, "manifest_signature": f.manifest_signature,
            "wrapped_dek": fk.wrapped_dek}


@router.get("/{file_id}/blob")
def file_blob(file_id: str, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    f, _ = _get_accessible(db, file_id, user)
    return FileResponse(f.blob_path, media_type="application/octet-stream")


@router.delete("/{file_id}")
def delete_file(file_id: str, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    f = _owned(db, file_id, user)
    db.query(FileKey).filter(FileKey.file_id == file_id).delete()
    if os.path.exists(f.blob_path):
        os.remove(f.blob_path)
    db.delete(f)
    db.commit()
    return {"ok": True}


# ---------------------------------------------------------------- Compartir / revocar
class ShareIn(BaseModel):
    username: str
    wrapped_dek: str  # DEK envuelta con la clave pública (verificada por huella) del destinatario


@router.get("/{file_id}/access")
def list_access(file_id: str, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    _owned(db, file_id, user)
    rows = db.execute(select(User.username).join(FileKey, FileKey.user_id == User.id)
                      .where(FileKey.file_id == file_id)).scalars().all()
    return {"users": rows}


@router.post("/{file_id}/share")
def share(file_id: str, body: ShareIn, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    _owned(db, file_id, user)
    target = db.scalar(select(User).where(User.username == body.username.lower()))
    if not target:
        raise HTTPException(404, "Destinatario no encontrado")
    existing = db.scalar(select(FileKey).where(FileKey.file_id == file_id, FileKey.user_id == target.id))
    if existing:
        existing.wrapped_dek = body.wrapped_dek
    else:
        db.add(FileKey(file_id=file_id, user_id=target.id, wrapped_dek=body.wrapped_dek))
    db.commit()
    return {"ok": True}


@router.delete("/{file_id}/share/{username}")
def revoke(file_id: str, username: str, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    """Quita la DEK envuelta del usuario. OJO: esto NO basta; si el usuario ya guardó la DEK
    puede seguir descifrando. El cliente debe a continuación subir una nueva versión con DEK
    nueva (PUT /files/{id}) para que la revocación sea efectiva."""
    _owned(db, file_id, user)
    target = db.scalar(select(User).where(User.username == username.lower()))
    if not target or target.id == user.id:
        raise HTTPException(400, "Usuario inválido")
    db.query(FileKey).filter(FileKey.file_id == file_id, FileKey.user_id == target.id).delete()
    db.commit()
    return {"ok": True, "next_step": "re-cifrar con una DEK nueva (PUT /files/{id})"}
