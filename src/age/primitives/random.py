import os

__all__ = ["random"]


def random(n: int) -> bytes:
    """Generate `n` random bytes suitable for cryptographic use

    Implemented through :func:`os.urandom`

    :param n: Number of random bytes to generate
    :returns: Random bytes
    """
    return os.urandom(n)
