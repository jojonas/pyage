import enum
import typing

from age.primitives import encode, random, hkdf, hmac_generate, hmac_verify
from age.keys.base import EncryptionKey, DecryptionKey
from age.recipients import (
    Recipient,
    generate_recipient_from_key,
    decrypt_file_key,
)
from age.stream import stream_decrypt, stream_encrypt


@enum.unique
class EncryptionAlgorithm(enum.Enum):
    CHACHAPOLY = "ChaChaPoly"


class PreliminaryHeader:
    def __init__(self):
        self.age_version: int = 1
        self.recipients: typing.List[Recipient] = []
        self.encryption_algorithm: EncryptionAlgorithm = EncryptionAlgorithm.CHACHAPOLY
        self.authentication_tag: bytes = b""
        self.data_to_authenticate: bytes = b""

    def unlock(self, keys: typing.Collection[DecryptionKey]):
        file_key = decrypt_file_key(self.recipients, keys)
        self._authenticate(file_key)
        return Header(
            file_key=file_key,
            recipients=self.recipients,
            age_version=self.age_version,
        )

    def _authenticate(self, file_key):
        key = hkdf(b"", b"header")(file_key, 32)
        hmac_verify(key, self.data_to_authenticate)(self.authentication_tag)


class Header:
    def __init__(
        self,
        file_key: bytes = None,
        recipients: typing.Collection[Recipient] = None,
        encryption_algorithm: EncryptionAlgorithm = EncryptionAlgorithm.CHACHAPOLY,
        age_version: int = 1,
    ):
        if recipients is None:
            recipients = []

        if file_key is None:
            file_key = random(16)

        self.file_key: bytes = file_key
        self.recipients: typing.List[Recipient] = list(recipients)
        self.encryption_algorithm: EncryptionAlgorithm = encryption_algorithm
        self.age_version: int = age_version

    def add_recipient(self, key: EncryptionKey):
        recipient = generate_recipient_from_key(key, self.file_key)
        self.recipients.append(recipient)

    def serialize_header(self) -> bytes:
        header = self._serialize_until_authentication()
        authentication_tag = self._authentication_tag(header)
        return (
            header + b" " + encode(authentication_tag).encode("ascii") + b"\n"
        )

    def _serialize_until_authentication(self) -> bytes:
        output = f"This is a file encrypted with age-tool.com, version {self.age_version}\n"
        for recipient in self.recipients:
            output += recipient.get_recipient_line() + "\n"
        output += "--- " + self.encryption_algorithm.value
        return output.encode("ascii")

    def _authentication_tag(self, data) -> bytes:
        key = hkdf(b"", b"header")(self.file_key, 32)
        return hmac_generate(key)(data)

    def decrypt(self, body: bytes) -> bytes:
        assert self.encryption_algorithm == EncryptionAlgorithm.CHACHAPOLY

        nonce = body[:16]
        ciphertext = body[16:]

        key = hkdf(nonce, b"payload")(self.file_key, 32)
        return stream_decrypt(key, ciphertext)

    def encrypt(self, data: bytes) -> bytes:
        assert self.encryption_algorithm == EncryptionAlgorithm.CHACHAPOLY

        nonce = random(16)
        key = hkdf(nonce, b"payload")(self.file_key, 32)
        ciphertext = stream_encrypt(key, data)
        return nonce + ciphertext
