"""Pruebas básicas del servidor. Ejecutar: pytest -q

El flujo WebAuthn completo requiere un autenticador real (navegador); aquí se
prueban las opciones, el rechazo de retos reutilizados y el resto de la API
creando sesiones directamente en la BD.
"""
import base64
import json
import os
import secrets
import tempfile

tmp = tempfile.mkdtemp()
os.environ["DATABASE_URL"] = f"sqlite:///{tmp}/test.db"
os.environ["BLOB_DIR"] = f"{tmp}/blobs"

from fastapi.testclient import TestClient  # noqa: E402

from app.db import SessionLocal, User, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.routers.audit import GENESIS, chain_hash  # noqa: E402
from app.security import new_session  # noqa: E402

init_db()
client = TestClient(app)


def make_user(name: str) -> dict:
    db = SessionLocal()
    u = User(username=name, webauthn_user_id=secrets.token_bytes(32))
    db.add(u)
    db.commit()
    token = new_session(db, u)
    db.close()
    return {"Authorization": f"Bearer {token}"}


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_register_options_and_challenge_single_use():
    r = client.post("/auth/register/options", json={"username": "alice_reg"})
    assert r.status_code == 200
    opts = r.json()
    assert opts["rp"]["id"] == "localhost"
    challenge = opts["challenge"]
    fake_client_data = b64url(json.dumps({"type": "webauthn.create", "challenge": challenge,
                                          "origin": "http://localhost:8080"}).encode())
    cred = {"id": "x", "rawId": "x", "type": "public-key",
            "response": {"clientDataJSON": fake_client_data, "attestationObject": "AA"}}
    # 1er intento: el reto se consume y la attestation falsa es rechazada
    r1 = client.post("/auth/register/verify", json={"username": "alice_reg", "credential": cred})
    assert r1.status_code == 400 and "rechazado" in r1.json()["detail"]
    # 2º intento con el mismo reto (replay): rechazado por reto ya usado
    r2 = client.post("/auth/register/verify", json={"username": "alice_reg", "credential": cred})
    assert r2.status_code == 400 and "utilizado" in r2.json()["detail"]


def test_requires_session():
    assert client.get("/files").status_code == 401
    assert client.get("/files", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_keys_files_share_revoke():
    a, b = make_user("alice"), make_user("bob")
    keys = {"enc_public_key": "RSA_PUB", "sig_public_key": "EC_PUB", "wrapped_private_keys": "{}",
            "kdf_salt": "c2FsdA==", "kdf_params": '{"alg":"argon2id"}'}
    assert client.put("/keys/me", json=keys, headers=a).status_code == 200
    assert client.put("/keys/me", json=keys, headers=b).status_code == 200
    pub = client.get("/keys/bob", headers=a).json()
    assert "wrapped_private_keys" not in pub  # nunca se expone lo envuelto de otros

    fid = client.post("/files/new-id", headers=a).json()["id"]
    manifest = json.dumps({"id": fid, "version": 1, "sha256": "ab"})
    r = client.post("/files", headers=a, data={"file_id": fid, "version": 1, "wrapped_dek": "DEK_A",
                                               "manifest": manifest, "manifest_signature": "SIG"},
                    files={"blob": ("x.bin", b"\x00cifrado")})
    assert r.status_code == 200, r.text
    assert client.get(f"/files/{fid}/blob", headers=b).status_code == 404  # bob sin acceso

    assert client.post(f"/files/{fid}/share", headers=a,
                       json={"username": "bob", "wrapped_dek": "DEK_B"}).status_code == 200
    assert client.get(f"/files/{fid}/meta", headers=b).json()["wrapped_dek"] == "DEK_B"
    assert client.get(f"/files/{fid}/blob", headers=b).content == b"\x00cifrado"

    assert client.delete(f"/files/{fid}/share/bob", headers=a).status_code == 200
    assert client.get(f"/files/{fid}/meta", headers=b).status_code == 404

    # Anti-rollback: no se acepta una versión <= actual
    m1 = json.dumps({"id": fid, "version": 1, "sha256": "cd"})
    r = client.put(f"/files/{fid}", headers=a, data={"version": 1, "manifest": m1, "manifest_signature": "S",
                                                     "wrapped_deks": "[]"}, files={"blob": ("x", b"1")})
    assert r.status_code == 409
    m2 = json.dumps({"id": fid, "version": 2, "sha256": "cd"})
    r = client.put(f"/files/{fid}", headers=a, data={"version": 2, "manifest": m2, "manifest_signature": "S",
                   "wrapped_deks": json.dumps([{"username": "alice", "wrapped_dek": "DEK_A2"}])},
                   files={"blob": ("x", b"nuevo")})
    assert r.status_code == 200, r.text
    assert client.get(f"/files/{fid}/meta", headers=a).json()["version"] == 2


def test_audit_chain():
    a = make_user("carol")
    head = client.get("/audit/head", headers=a).json()["hash"]
    assert head == GENESIS
    ev = '{"action":"upload"}'
    h = chain_hash(head, ev)
    assert client.post("/audit", headers=a, json={"event": ev, "prev_hash": head,
                                                  "entry_hash": h, "signature": "SIG"}).status_code == 200
    # prev_hash viejo -> rechazado
    assert client.post("/audit", headers=a, json={"event": ev, "prev_hash": head,
                                                  "entry_hash": h, "signature": "SIG"}).status_code == 409
    assert client.get("/audit/verify-chain", headers=a).json() == {"ok": True}
