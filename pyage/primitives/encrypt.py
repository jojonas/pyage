from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

ZERO_NONCE = b"\00" * 12


def _cipher(key):
    return ChaCha20Poly1305(key=key)


def encrypt(key, plaintext):
    return _cipher(key).encrypt(ZERO_NONCE, plaintext, None)


def decrypt(key, ciphertext):
    return _cipher(key).decrypt(ZERO_NONCE, ciphertext, None)
