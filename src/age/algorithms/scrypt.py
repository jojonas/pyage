import typing

from age.keys.password import PasswordKey
from age.primitives.encrypt import decrypt, encrypt
from age.primitives.random import random
from age.primitives.scrypt import scrypt

__all__ = ["scrypt_encrypt_file_key", "scrypt_decrypt_file_key"]


def scrypt_encrypt_file_key(
    password: PasswordKey, file_key: bytes
) -> typing.Tuple[bytes, int, bytes]:
    # https://blog.filippo.io/the-scrypt-parameters/

    salt = random(16)
    log_cost = 18  # about 1 second
    cost = 1 << log_cost

    key = scrypt(salt, cost, password.value)
    assert len(key) == 32
    encrypted_file_key = encrypt(key, file_key)

    return salt, log_cost, encrypted_file_key


def scrypt_decrypt_file_key(
    password: PasswordKey, salt: bytes, log_cost: int, encrypted_file_key: bytes
) -> bytes:
    if not (2 <= log_cost <= 22):
        raise ValueError("Invalid scrypt cost")

    cost = 1 << log_cost
    key = scrypt(salt, cost, password.value)
    return decrypt(key, encrypted_file_key)
