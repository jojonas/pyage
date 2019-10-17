from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

__all__ = ["encrypt", "decrypt"]


ZERO_NONCE = b"\00" * 12


def _cipher(key: bytes) -> ChaCha20Poly1305:
    return ChaCha20Poly1305(key=key)


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt `plaintext` with the 32 byte `key` using ChaCha20 + Poly1305 (:rfc:`7539`) using a zero nonce.

    :param key: 32-byte key
    :param plaintext: Data to encrypt
    :returns: Ciphertext
    """
    return _cipher(key).encrypt(ZERO_NONCE, plaintext, None)


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt `plaintext` with the 32 byte `key` ChaCha20 + Poly1305 (:rfc:`7539`) using a zero nonce.

    :param key: 32-byte key
    :param ciphertext: Ciphertext
    :returns: Decrypted data
    :raises cryptography.exceptions.InvalidTag: if authentication fails
    """
    return _cipher(key).decrypt(ZERO_NONCE, ciphertext, None)
