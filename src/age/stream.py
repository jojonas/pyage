import math

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PLAINTEXT_BLOCK_SIZE = 64 * 1024
CIPHERTEXT_BLOCK_SIZE = PLAINTEXT_BLOCK_SIZE + 16

NONCE_COUNTER_MAX = 2 ** (8 * 11) - 1


def _pack_nonce(nonce: int, last_block: bool = False) -> bytes:
    assert nonce <= NONCE_COUNTER_MAX, "Stream nonce wrapped around"
    return nonce.to_bytes(11, byteorder="big", signed=False) + (b"\x01" if last_block else b"\x00")


def _chunk(data, size):
    for i in range(0, len(data), size):
        yield data[i : i + size]


def stream_encrypt(key: bytes, data: bytes) -> bytes:
    assert len(key) == 32

    aead = ChaCha20Poly1305(key)
    blocks = math.ceil(len(data) / PLAINTEXT_BLOCK_SIZE)

    encrypted = b""
    for nonce, block in enumerate(_chunk(data, PLAINTEXT_BLOCK_SIZE)):
        last_block = nonce == blocks - 1
        packed_nonce = _pack_nonce(nonce, last_block=last_block)

        encrypted += aead.encrypt(nonce=packed_nonce, data=block, associated_data=None)

    return encrypted


def stream_decrypt(key: bytes, data: bytes) -> bytes:
    assert len(key) == 32

    aead = ChaCha20Poly1305(key)
    blocks = math.ceil(len(data) / CIPHERTEXT_BLOCK_SIZE)

    decrypted = b""
    for nonce, block in enumerate(_chunk(data, CIPHERTEXT_BLOCK_SIZE)):
        last_block = nonce == blocks - 1
        packed_nonce = _pack_nonce(nonce, last_block=last_block)

        decrypted += aead.decrypt(nonce=packed_nonce, data=block, associated_data=None)

    return decrypted
