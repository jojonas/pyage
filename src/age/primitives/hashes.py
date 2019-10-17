import hashlib

__all__ = ["sha256"]


def sha256(data: bytes) -> bytes:
    """Compute the SHA-256 digest

    :param data: Data to hash
    :returns: Raw digest (32 byte)

    >>> h = sha256(b'test')
    >>> len(h)
    32
    >>> h.hex()
    '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
    """

    return hashlib.sha256(data).digest()
