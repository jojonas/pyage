import os

from age.algorithms.ssh_rsa import (
    ssh_rsa_encrypt_file_key,
    ssh_rsa_decrypt_file_key,
)
from age.keys import RSAPrivateKey, RSAPublicKey


def test_rsa_algorithm():
    key = RSAPrivateKey.generate()

    file_key = os.urandom(16)

    args = ssh_rsa_encrypt_file_key(key.public_key(), file_key)
    decrypted = ssh_rsa_decrypt_file_key(key, *args)

    assert decrypted == file_key
