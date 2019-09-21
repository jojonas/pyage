from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__all__ = ["hkdf"]


def hkdf(salt: bytes, label: bytes, key: bytes, len: int) -> bytes:
    """Derive a key of len `len` using HKDF (:rfc:`5869`) with SHA-256"""
    return HKDF(
        algorithm=hashes.SHA256(), length=len, salt=salt, info=label, backend=default_backend()
    ).derive(key)
