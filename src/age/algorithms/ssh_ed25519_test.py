import os

from pytest import raises

from age.algorithms.ssh_ed25519 import ssh_ed25519_decrypt_file_key, ssh_ed25519_encrypt_file_key
from age.keys.ed25519 import Ed25519PrivateKey


def test_ed25519_algorithm():
    key = Ed25519PrivateKey.generate()

    file_key = os.urandom(16)

    args = ssh_ed25519_encrypt_file_key(key.public_key(), file_key)
    decrypted = ssh_ed25519_decrypt_file_key(key, *args)

    assert decrypted == file_key


def test_ed25519_failed_decryption():
    key = Ed25519PrivateKey.generate()

    file_key = os.urandom(16)

    args = ssh_ed25519_encrypt_file_key(key.public_key(), file_key)
    args_new = (b"\xAA" * 4, *args[1:])

    with raises(ValueError):
        ssh_ed25519_decrypt_file_key(key, *args_new)

    with raises(ValueError):
        ssh_ed25519_decrypt_file_key(Ed25519PrivateKey.generate(), *args)
