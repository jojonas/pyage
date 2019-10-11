import typing

from age.algorithms.ssh_rsa import ssh_rsa_decrypt_file_key, ssh_rsa_encrypt_file_key
from age.keys.base import DecryptionKey, EncryptionKey
from age.keys.rsa import RSAPrivateKey, RSAPublicKey
from age.primitives.encode import decode, encode
from age.recipients.base import Recipient


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
        fingerprint, encrypted_file_key = ssh_rsa_encrypt_file_key(password_key, file_key)
        return cls(fingerprint, encrypted_file_key)

    @classmethod
    def load(cls, args: typing.List[str], body: str):
        return cls(decode(args[0]), decode(body))

    def dump(self) -> typing.Tuple[typing.List[str], str]:
        return [encode(self.fingerprint)], encode(self.encrypted_file_key)

    def decrypt(self, password_key: DecryptionKey) -> bytes:
        assert isinstance(password_key, RSAPrivateKey)
        return ssh_rsa_decrypt_file_key(password_key, self.fingerprint, self.encrypted_file_key)
