"""Log de auditoría encadenado por hash.

h_i = SHA-256(h_{i-1} || evento_i). El cliente calcula el hash, lo firma con su
clave ECDSA y lo envía; el servidor comprueba que encadena con la última entrada.
Cualquiera puede descargar el log y verificar cadena + firmas.
"""
import hashlib

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession

from ..db import AuditEntry, User, get_db
from ..security import current_user

router = APIRouter(prefix="/audit", tags=["audit"])

GENESIS = "0" * 64


def chain_hash(prev_hash: str, event: str) -> str:
    return hashlib.sha256(bytes.fromhex(prev_hash) + event.encode("utf-8")).hexdigest()


class AuditIn(BaseModel):
    event: str        # JSON canónico: {"action":"upload","file":"...","version":1,"ts":"..."}
    prev_hash: str
    entry_hash: str
    signature: str    # ECDSA P-256 del actor sobre entry_hash (base64)


@router.get("/head")
def head(_: User = Depends(current_user), db: DBSession = Depends(get_db)):
    last = db.scalar(select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1))
    return {"seq": last.seq if last else 0, "hash": last.entry_hash if last else GENESIS}


@router.post("")
def append(body: AuditIn, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    last = db.scalar(select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1))
    tip = last.entry_hash if last else GENESIS
    if body.prev_hash != tip:
        raise HTTPException(409, "prev_hash no coincide con la cabeza del log; vuelve a pedir /audit/head")
    if chain_hash(body.prev_hash, body.event) != body.entry_hash:
        raise HTTPException(400, "entry_hash incorrecto")
    db.add(AuditEntry(actor_id=user.id, event=body.event, prev_hash=body.prev_hash,
                      entry_hash=body.entry_hash, signature=body.signature))
    db.commit()
    return {"ok": True}


@router.get("")
def get_log(_: User = Depends(current_user), db: DBSession = Depends(get_db)):
    rows = db.execute(select(AuditEntry, User.username).join(User, User.id == AuditEntry.actor_id)
                      .order_by(AuditEntry.seq)).all()
    return [{"seq": e.seq, "actor": name, "event": e.event, "prev_hash": e.prev_hash,
             "entry_hash": e.entry_hash, "signature": e.signature,
             "created_at": e.created_at.isoformat()} for e, name in rows]


@router.get("/verify-chain")
def verify_chain(_: User = Depends(current_user), db: DBSession = Depends(get_db)):
    """Verificación de la cadena (las firmas las verifica el cliente con las claves públicas)."""
    prev = GENESIS
    for e in db.scalars(select(AuditEntry).order_by(AuditEntry.seq)):
        if e.prev_hash != prev or chain_hash(prev, e.event) != e.entry_hash:
            return {"ok": False, "broken_at": e.seq}
        prev = e.entry_hash
    return {"ok": True}
