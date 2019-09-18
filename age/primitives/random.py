import os

__all__ = ['random']


def random(n: int) -> bytes:
    return os.urandom(n)
