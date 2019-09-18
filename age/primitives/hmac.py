import typing

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC

__all__ = ['hmac']


def hmac(key: bytes) -> typing.Callable[[bytes], bytes]:
    if len(key) > 32:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(key)
        key = digest.finalize()

    assert len(key) <= 32

    def func(message: bytes) -> bytes:
        mac = HMAC(
            key=key,
            algorithm=hashes.SHA256(),
            backend=default_backend())
        mac.update(message)
        return mac.finalize()
    return func
