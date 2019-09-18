import typing

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

__all__ = ["encrypt", "decrypt"]


ZERO_NONCE = b"\00" * 12


def _cipher(key: bytes) -> ChaCha20Poly1305:
    return ChaCha20Poly1305(key=key)


def encrypt(key: bytes) -> typing.Callable[[bytes], bytes]:
    cipher = _cipher(key)

    def func(plaintext: bytes) -> bytes:
        return cipher.encrypt(ZERO_NONCE, plaintext, None)

    return func


def decrypt(key: bytes) -> typing.Callable[[bytes], bytes]:
    cipher = _cipher(key)

    def func(ciphertext: bytes) -> bytes:
        return cipher.decrypt(ZERO_NONCE, ciphertext, None)

    return func
