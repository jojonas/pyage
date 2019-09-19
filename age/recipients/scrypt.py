import typing

from age.algorithms import scrypt_encrypt_file_key, scrypt_decrypt_file_key
from age.keys import PasswordKey
from age.keys.base import EncryptionKey, DecryptionKey
from age.primitives import encode, decode
from .base import Recipient


class SCryptRecipient(Recipient):
    TAG: str = "scrypt"
    ENCRYPTION_KEY_TYPE: typing.Type[EncryptionKey] = PasswordKey
    DECRYPTION_KEY_TYPE: typing.Type[DecryptionKey] = PasswordKey

    def __init__(self, salt: bytes, cost: int, encrypted_file_key: bytes):
        self.salt: bytes = salt
        self.cost: int = cost
        self.encrypted_file_key: bytes = encrypted_file_key

    @classmethod
    def generate(cls, password_key: EncryptionKey, file_key: bytes):
        assert isinstance(password_key, PasswordKey)
        salt, cost, encrypted_file_key = scrypt_encrypt_file_key(
            password_key, file_key
        )
        return cls(salt, cost, encrypted_file_key)

    @classmethod
    def from_tokens(cls, tokens: typing.List[str]):
        return cls(decode(tokens[0]), int(tokens[1]), decode(tokens[2]))

    def get_tokens(self) -> typing.Collection[str]:
        return (
            encode(self.salt),
            str(self.cost),
            encode(self.encrypted_file_key),
        )

    def decrypt(self, password_key: DecryptionKey) -> bytes:
        assert isinstance(password_key, PasswordKey)
        return scrypt_decrypt_file_key(
            password_key, self.salt, self.cost, self.encrypted_file_key
        )
