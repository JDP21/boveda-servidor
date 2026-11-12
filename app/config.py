"""Configuración leída de variables de entorno (.env). Nunca poner secretos aquí."""
import os

# WebAuthn: la credencial queda ligada a este dominio (relying party)
RP_ID = os.getenv("RP_ID", "localhost")
RP_NAME = os.getenv("RP_NAME", "Bóveda Segura UD")
ORIGIN = os.getenv("ORIGIN", "http://localhost:8080")

# Base de datos: SQLite por defecto para desarrollo; PostgreSQL en Docker
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./boveda.db")

# Carpeta donde se guardan los archivos YA CIFRADOS por el cliente
BLOB_DIR = os.getenv("BLOB_DIR", "./data/blobs")

# Tiempos de vida
CHALLENGE_TTL_SECONDS = int(os.getenv("CHALLENGE_TTL_SECONDS", "300"))
SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MINUTES", "60"))

# Tamaño máximo de archivo (bytes)
MAX_FILE_BYTES = int(os.getenv("MAX_FILE_BYTES", str(50 * 1024 * 1024)))
