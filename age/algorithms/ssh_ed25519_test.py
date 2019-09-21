import os

from age.algorithms.ssh_ed25519 import (
    ssh_ed25519_decrypt_file_key,
    ssh_ed25519_encrypt_file_key,
)
from age.keys import Ed25519PrivateKey, Ed25519PublicKey


def test_ed25519_algorithm():
    key = Ed25519PrivateKey.generate()

    file_key = os.urandom(16)

    args = ssh_ed25519_encrypt_file_key(key.public_key(), file_key)
    decrypted = ssh_ed25519_decrypt_file_key(key, *args)

    assert decrypted == file_key
