import typing

from age.algorithms.ssh_ed25519 import ssh_ed25519_decrypt_file_key, ssh_ed25519_encrypt_file_key
from age.keys.base import DecryptionKey, EncryptionKey
from age.keys.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from age.primitives.encode import decode, encode
from age.primitives.x25519 import ECPoint
from age.recipients.base import Recipient


class SSHED25519Recipient(Recipient):
    TAG: str = "ssh-ed25519"
    ENCRYPTION_KEY_TYPE: typing.Type[EncryptionKey] = Ed25519PublicKey
    DECRYPTION_KEY_TYPE: typing.Type[DecryptionKey] = Ed25519PrivateKey

    def __init__(self, fingerprint: bytes, derived_secret: ECPoint, encrypted_file_key: bytes):
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
    def load(cls, args: typing.List[str], body: str):
        return cls(decode(args[0]), ECPoint(decode(args[1])), decode(body))

    def dump(self) -> typing.Tuple[typing.List[str], str]:
        return (
            [encode(self.fingerprint), encode(self.derived_secret)],
            encode(self.encrypted_file_key),
        )

    def decrypt(self, password_key: DecryptionKey) -> bytes:
        assert isinstance(password_key, Ed25519PrivateKey)
        return ssh_ed25519_decrypt_file_key(
            password_key, self.fingerprint, self.derived_secret, self.encrypted_file_key
        )
