import typing

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__all__ = ['hkdf']


def hkdf(salt: bytes, label: bytes) -> typing.Callable[[bytes, int], bytes]:
    def func(key: bytes, len: int) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=len,
            salt=salt,
            info=label,
            backend=default_backend()
        ).derive(key)
    return func
