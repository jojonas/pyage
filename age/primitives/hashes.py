import hashlib

__all__ = ["sha256"]


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
