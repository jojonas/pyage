import typing

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC

__all__ = ['hmac_generate', 'hmac_verify']


def _reduce_key(key: bytes) -> bytes:
    if len(key) > 32:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(key)
        key = digest.finalize()
    return key


def _hmac_obj(key: bytes) -> HMAC:
    return HMAC(
        key=key,
        algorithm=hashes.SHA256(),
        backend=default_backend())


def hmac_generate(key: bytes) -> typing.Callable[[bytes], bytes]:
    key = _reduce_key(key)
    assert len(key) <= 32

    mac = _hmac_obj(key)

    def func(message: bytes) -> bytes:
        mac.update(message)
        return mac.finalize()
    return func


def hmac_verify(key: bytes, message: bytes) -> typing.Callable[[bytes], None]:
    key = _reduce_key(key)
    assert len(key) <= 32

    mac = _hmac_obj(key)
    mac.update(message)

    def func(tag: bytes) -> None:
        mac.verify(tag)

    return func
