import os

__all__ = ["random"]


def random(n: int) -> bytes:
    """Generate `n` random bytes suitable for cryptographic use

    Implemented through :func:`os.urandom`"""
    return os.urandom(n)
