import typing

from age.algorithms import x25519_encrypt_file_key, x25519_decrypt_file_key
from age.keys import AgePrivateKey, AgePublicKey
from age.keys.base import EncryptionKey, DecryptionKey
from age.primitives import encode, decode, ECPoint
from .base import Recipient


class X25519Recipient(Recipient):
    TAG: str = "X25519"
    ENCRYPTION_KEY_TYPE: typing.Type[EncryptionKey] = AgePublicKey
    DECRYPTION_KEY_TYPE: typing.Type[DecryptionKey] = AgePrivateKey

    def __init__(self, derived_secret: ECPoint, encrypted_file_key: bytes):
        self.derived_secret: ECPoint = derived_secret
        self.encrypted_file_key: bytes = encrypted_file_key

    @classmethod
    def generate(cls, public_key: EncryptionKey, file_key: bytes):
        assert isinstance(public_key, AgePublicKey)
        derived_secret, encrypted_file_key = x25519_encrypt_file_key(
            public_key, file_key
        )
        return cls(derived_secret, encrypted_file_key)

    @classmethod
    def from_tokens(cls, tokens: typing.List[str]):
        return cls(ECPoint(decode(tokens[0])), decode(tokens[1]))

    def get_tokens(self) -> typing.Collection[str]:
        return (encode(self.derived_secret), encode(self.encrypted_file_key))

    def decrypt(self, private_key: DecryptionKey) -> bytes:
        assert isinstance(private_key, AgePrivateKey)
        return x25519_decrypt_file_key(
            private_key, self.derived_secret, self.encrypted_file_key
        )
