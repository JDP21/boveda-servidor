# boveda-servidor

API del proyecto **Bóveda de archivos compartidos con cifrado del lado del cliente y autenticación sin contraseña** (Criptografía Aplicada — UD, Alternativa B).

El servidor es **honesto pero curioso**: verifica passkeys, controla el acceso y almacena datos, pero **nunca puede descifrar nada**. Solo guarda claves públicas, claves privadas envueltas, DEK envueltas, archivos cifrados, manifiestos firmados y el log encadenado.

## Stack
- Python 3.12 + FastAPI
- `py_webauthn` para registrar y verificar passkeys
- SQLAlchemy (SQLite en desarrollo, PostgreSQL en Docker)

## Ejecutar en local (sin Docker)
```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env
uvicorn app.main:app --reload --port 8000
```
Documentación interactiva: http://localhost:8000/docs

Pruebas: `pytest -q`

Para levantar todo el sistema (cliente, API y base de datos) usa el repositorio **boveda-infra**.

## Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| POST | `/auth/register/options` | Reto de registro (32 B, un solo uso, expira) |
| POST | `/auth/register/verify` | Verifica la credencial y guarda su clave pública y contador → token |
| POST | `/auth/login/options` | Reto de inicio de sesión |
| POST | `/auth/login/verify` | Verifica la firma, consume el reto y actualiza el contador → token |
| PUT / GET | `/keys/me` | Guarda o lee tus claves públicas y privadas **envueltas** |
| GET | `/keys/{usuario}` | Claves **públicas** de otro usuario (el cliente debe verificar la huella) |
| POST | `/files/new-id` | Id para incluir en el manifiesto y en los datos asociados de GCM |
| POST | `/files` | Sube el archivo cifrado, la DEK envuelta y el manifiesto firmado |
| PUT | `/files/{id}` | Nueva versión o re-cifrado tras revocar (exige versión mayor: anti-rollback) |
| GET | `/files` | Lista los archivos a los que tienes acceso |
| GET | `/files/{id}/meta` | Manifiesto, firma y tu DEK envuelta |
| GET | `/files/{id}/blob` | Archivo cifrado |
| DELETE | `/files/{id}` | Eliminar (solo el propietario) |
| GET | `/files/{id}/access` | Quién tiene acceso |
| POST | `/files/{id}/share` | Compartir (DEK envuelta para el destinatario) |
| DELETE | `/files/{id}/share/{usuario}` | Revocar (luego hay que re-cifrar con DEK nueva) |
| GET | `/audit/head` | Último hash del log |
| POST | `/audit` | Agrega un evento: `h_i = SHA-256(h_{i-1} ‖ evento)` firmado por el actor |
| GET | `/audit`, `/audit/verify-chain` | Lee el log y verifica la cadena |

Autenticación: encabezado `Authorization: Bearer <token>`, con un token opaco de 256 bits que expira.

## Defensas implementadas en el servidor
- **Replay de WebAuthn:** el reto es de un solo uso y se marca como usado **antes** de verificar.
- **Phishing desde otro dominio:** se valida `expected_origin` y `expected_rp_id`.
- **Rollback:** no se acepta una versión menor o igual a la actual (además, la versión va en el manifiesto firmado).
- **Log alterado:** cada entrada debe encadenar con la cabeza actual; `/audit/verify-chain` detecta rupturas.
- **Volcado de la BD:** solo contiene material público o cifrado por el cliente.

## Secretos
El archivo `.env` está en `.gitignore`. Nunca subas claves, contraseñas ni tokens: si aparecen en el historial de Git, el criterio C8 queda en insuficiente.
