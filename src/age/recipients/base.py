import abc
import typing

from age.keys.base import DecryptionKey, EncryptionKey


class Recipient:
    TAG: str
    ENCRYPTION_KEY_TYPE: typing.Type[EncryptionKey]
    DECRYPTION_KEY_TYPE: typing.Type[DecryptionKey]

    def get_recipient_line(self):
        return " ".join(["->", self.TAG, *self.get_tokens()])

    @abc.abstractmethod
    def decrypt(self, key: DecryptionKey) -> bytes:
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def generate(self, key: EncryptionKey, file_key: bytes):
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def from_tokens(cls, tokens: typing.List[str]):
        raise NotImplementedError

    @abc.abstractmethod
    def get_tokens(self) -> typing.Collection[str]:
        raise NotImplementedError
