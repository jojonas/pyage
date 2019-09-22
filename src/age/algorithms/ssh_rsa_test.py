import os

from pytest import raises

from age.algorithms.ssh_rsa import ssh_rsa_decrypt_file_key, ssh_rsa_encrypt_file_key
from age.keys.rsa import RSAPrivateKey


def test_rsa_algorithm():
    key = RSAPrivateKey.generate()

    file_key = os.urandom(16)

    args = ssh_rsa_encrypt_file_key(key.public_key(), file_key)
    decrypted = ssh_rsa_decrypt_file_key(key, *args)

    assert decrypted == file_key


def test_rsa_failed_decryption():
    key = RSAPrivateKey.generate()

    file_key = os.urandom(16)

    args = ssh_rsa_encrypt_file_key(key.public_key(), file_key)
    args_new = (b"\xAA" * 4, *args[1:])

    with raises(ValueError):
        ssh_rsa_decrypt_file_key(key, *args_new)

    with raises(ValueError):
        ssh_rsa_decrypt_file_key(RSAPrivateKey.generate(), *args)
