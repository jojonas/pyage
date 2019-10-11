import abc
import typing

from age.keys.base import DecryptionKey, EncryptionKey


class Recipient:
    TAG: str
    ENCRYPTION_KEY_TYPE: typing.Type[EncryptionKey]
    DECRYPTION_KEY_TYPE: typing.Type[DecryptionKey]

    @abc.abstractmethod
    def decrypt(self, key: DecryptionKey) -> bytes:
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def generate(self, key: EncryptionKey, file_key: bytes):
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def load(cls, args: typing.List[str], body: str):
        raise NotImplementedError

    @abc.abstractmethod
    def dump(self) -> typing.Tuple[typing.List[str], str]:
        raise NotImplementedError
