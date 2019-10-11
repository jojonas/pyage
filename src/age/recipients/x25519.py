import typing

from age.algorithms.x25519 import x25519_decrypt_file_key, x25519_encrypt_file_key
from age.keys.agekey import AgePrivateKey, AgePublicKey
from age.keys.base import DecryptionKey, EncryptionKey
from age.primitives.encode import decode, encode
from age.primitives.x25519 import ECPoint
from age.recipients.base import Recipient


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
        derived_secret, encrypted_file_key = x25519_encrypt_file_key(public_key, file_key)
        return cls(derived_secret, encrypted_file_key)

    @classmethod
    def load(cls, args: typing.List[str], body: str):
        return cls(ECPoint(decode(args[0])), decode(body))

    def dump(self) -> typing.Tuple[typing.List[str], str]:
        return [encode(self.derived_secret)], encode(self.encrypted_file_key)

    def decrypt(self, private_key: DecryptionKey) -> bytes:
        assert isinstance(private_key, AgePrivateKey)
        return x25519_decrypt_file_key(private_key, self.derived_secret, self.encrypted_file_key)
