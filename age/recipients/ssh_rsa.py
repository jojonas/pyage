import typing

from age.algorithms import ssh_rsa_encrypt_file_key, ssh_rsa_decrypt_file_key
from age.keys import RSAPrivateKey, RSAPublicKey
from age.keys.base import EncryptionKey, DecryptionKey
from age.primitives import encode, decode
from .base import Recipient


class SSHRSARecipient(Recipient):
    TAG: str = "ssh-rsa"
    ENCRYPTION_KEY_TYPE: typing.Type[EncryptionKey] = RSAPublicKey
    DECRYPTION_KEY_TYPE: typing.Type[DecryptionKey] = RSAPrivateKey

    def __init__(self, fingerprint: bytes, encrypted_file_key: bytes):
        self.fingerprint: bytes = fingerprint
        self.encrypted_file_key: bytes = encrypted_file_key

    @classmethod
    def generate(cls, password_key: EncryptionKey, file_key: bytes):
        assert isinstance(password_key, RSAPublicKey)
        fingerprint, encrypted_file_key = ssh_rsa_encrypt_file_key(
            password_key, file_key
        )
        return cls(fingerprint, encrypted_file_key)

    @classmethod
    def from_tokens(cls, tokens: typing.List[str]):
        return cls(decode(tokens[0]), decode(tokens[1]))

    def get_tokens(self) -> typing.Collection[str]:
        return (encode(self.fingerprint), encode(self.encrypted_file_key))

    def decrypt(self, password_key: DecryptionKey) -> bytes:
        assert isinstance(password_key, RSAPrivateKey)
        return ssh_rsa_decrypt_file_key(
            password_key, self.fingerprint, self.encrypted_file_key
        )
