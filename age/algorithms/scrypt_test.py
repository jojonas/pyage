import os

from age.algorithms.scrypt import (
    scrypt_encrypt_file_key,
    scrypt_decrypt_file_key,
)
from age.keys import PasswordKey


def test_scrypt_algorithm():
    password = PasswordKey(os.urandom(10))

    file_key = os.urandom(16)

    args = scrypt_encrypt_file_key(password, file_key)
    decrypted = scrypt_decrypt_file_key(password, *args)

    assert decrypted == file_key
