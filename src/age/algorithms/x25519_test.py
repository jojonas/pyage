import os

from age.algorithms.x25519 import x25519_decrypt_file_key, x25519_encrypt_file_key
from age.keys.agekey import AgePrivateKey


def test_x25519_algorithm():
    key = AgePrivateKey.generate()

    file_key = os.urandom(16)

    args = x25519_encrypt_file_key(key.public_key(), file_key)
    decrypted = x25519_decrypt_file_key(key, *args)

    assert decrypted == file_key
