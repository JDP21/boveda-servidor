import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import ORIGIN
from .db import init_db
from .routers import audit, auth, files, keys


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


# ROOT_PATH=/api cuando corre detrás de nginx, para que /api/docs funcione
app = FastAPI(lifespan=lifespan, root_path=os.getenv("ROOT_PATH", ""), title="Bóveda Segura — API", version="0.1.0",
              description="Servidor 'honesto pero curioso': solo almacena material público o cifrado.")

# En Docker el cliente y la API comparten origen vía nginx (/api); CORS solo para desarrollo local.
app.add_middleware(CORSMiddleware, allow_origins=[ORIGIN], allow_credentials=False,
                   allow_methods=["*"], allow_headers=["Authorization", "Content-Type"])


@app.get("/health")
def health():
    return {"status": "ok"}


for r in (auth.router, keys.router, files.router, audit.router):
    app.include_router(r)
