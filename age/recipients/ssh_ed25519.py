import typing

from age.algorithms import (
    ssh_ed25519_encrypt_file_key,
    ssh_ed25519_decrypt_file_key,
)
from age.keys import Ed25519PrivateKey, Ed25519PublicKey
from age.keys.base import EncryptionKey, DecryptionKey
from age.primitives import encode, decode, ECPoint
from .base import Recipient


class SSHED25519Recipient(Recipient):
    TAG: str = "ssh-ed25519"
    ENCRYPTION_KEY_TYPE: typing.Type[EncryptionKey] = Ed25519PublicKey
    DECRYPTION_KEY_TYPE: typing.Type[DecryptionKey] = Ed25519PrivateKey

    def __init__(
        self,
        fingerprint: bytes,
        derived_secret: ECPoint,
        encrypted_file_key: bytes,
    ):
        self.fingerprint: bytes = fingerprint
        self.derived_secret: ECPoint = derived_secret
        self.encrypted_file_key: bytes = encrypted_file_key

    @classmethod
    def generate(cls, password_key: EncryptionKey, file_key: bytes):
        assert isinstance(password_key, Ed25519PublicKey)
        fingerprint, derived_secret, encrypted_file_key = ssh_ed25519_encrypt_file_key(
            password_key, file_key
        )
        return cls(fingerprint, derived_secret, encrypted_file_key)

    @classmethod
    def from_tokens(cls, tokens: typing.List[str]):
        return cls(
            decode(tokens[0]), ECPoint(decode(tokens[1])), decode(tokens[2])
        )

    def get_tokens(self) -> typing.Collection[str]:
        return (encode(self.fingerprint), encode(self.encrypted_file_key))

    def decrypt(self, password_key: DecryptionKey) -> bytes:
        assert isinstance(password_key, Ed25519PrivateKey)
        return ssh_ed25519_decrypt_file_key(
            password_key,
            self.fingerprint,
            self.derived_secret,
            self.encrypted_file_key,
        )
