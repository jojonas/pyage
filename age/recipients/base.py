import abc
import typing

from cryptography.exceptions import InvalidSignature

from age.keys.base import EncryptionKey, DecryptionKey


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


def _filter_keys_for_recipient(
    recipient: Recipient, keys: typing.Collection[DecryptionKey]
):
    return set(k for k in keys if isinstance(k, recipient.DECRYPTION_KEY_TYPE))


def decrypt_file_key(
    recipients: typing.Collection[Recipient],
    keys: typing.Collection[DecryptionKey],
) -> bytes:
    for recipient in recipients:
        for key in _filter_keys_for_recipient(recipient, keys):
            try:
                return recipient.decrypt(key)
            except InvalidSignature:
                continue

    raise ValueError("No matching key")


def parse_recipient_line(line: str) -> Recipient:
    assert line.startswith("-> ")

    _, tag, *arguments = line.split()
    for subclass in Recipient.__subclasses__():
        if subclass.TAG == tag:
            return subclass.from_tokens(arguments)

    raise ValueError("Cannot parse recipient line: Unknown recipient type")


def generate_recipient_from_key(
    key: EncryptionKey, file_key: bytes
) -> Recipient:
    for subclass in Recipient.__subclasses__():
        if isinstance(key, subclass.ENCRYPTION_KEY_TYPE):
            return subclass.generate(key, file_key)

    raise ValueError("Cannot generate recipient: Unknown encryption key type")
