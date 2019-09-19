import typing
from age.primitives import random, scrypt, encrypt, decrypt, encode, decode
from age.keys import PasswordKey

__all__ = [
    "scrypt_encrypt_file_key",
    "scrypt_decrypt_file_key",
    "SCRYPT_RECIPIENT_LABEL",
]

SCRYPT_RECIPIENT_LABEL = "scrypt"


def scrypt_encrypt_file_key(
    password: PasswordKey, file_key: bytes
) -> typing.Tuple[bytes, int, bytes]:

    salt = random(19)
    cost = 32768  # whats an appropriate cost?

    key = scrypt(salt, cost)(password.value)
    assert len(key) == 32
    encrypted_file_key = encrypt(key)(file_key)

    return salt, cost, encrypted_file_key


def scrypt_decrypt_file_key(
    password: PasswordKey, salt: bytes, cost: int, encrypted_file_key: bytes
) -> bytes:
    key = scrypt(salt, cost)(password.value)
    return decrypt(key)(encrypted_file_key)
