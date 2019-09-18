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
) -> typing.Tuple[str, str, str, str]:

    salt = random(19)
    cost = 32768  # whats an appropriate cost?

    key = scrypt(salt, cost)(password.value)
    assert len(key) == 32
    encrypted = encrypt(key)(file_key)

    return SCRYPT_RECIPIENT_LABEL, encode(salt), str(cost), encode(encrypted)


def scrypt_decrypt_file_key(
    password: PasswordKey, salt: str, cost: str, encrypted: str
) -> bytes:

    salt_bytes = decode(salt)
    encrypted_bytes = decode(encrypted)

    key = scrypt(salt_bytes, int(cost))(password.value)
    decrypted = decrypt(key)(encrypted_bytes)

    return decrypted
