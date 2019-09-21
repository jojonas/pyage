import hashlib

__all__ = ["sha256"]


def sha256(data: bytes) -> bytes:
    """Compute the SHA-256 digest"""

    return hashlib.sha256(data).digest()
