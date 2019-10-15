import os

from pytest import raises

from age.algorithms.scrypt import scrypt_decrypt_file_key, scrypt_encrypt_file_key
from age.keys.password import PasswordKey


def test_scrypt_algorithm():
    password = PasswordKey(os.urandom(10))
    file_key = os.urandom(16)

    args = scrypt_encrypt_file_key(password, file_key, log_cost=16)
    assert args[1] == 16
    decrypted = scrypt_decrypt_file_key(password, *args)

    assert decrypted == file_key


def test_scrypt_costs():
    password = PasswordKey(os.urandom(10))
    file_key = os.urandom(16)

    salt, log_cost, encrypted_file_key = scrypt_encrypt_file_key(password, file_key, log_cost=16)
    assert log_cost == 16

    assert scrypt_decrypt_file_key(password, salt, log_cost, encrypted_file_key)
    with raises(ValueError):
        scrypt_decrypt_file_key(password, salt, 100, encrypted_file_key)

    with raises(ValueError):
        scrypt_decrypt_file_key(password, salt, -1, encrypted_file_key)
