import typing

from cryptography.exceptions import InvalidTag

from age.exceptions import NoIdentity, UnknownRecipient
from age.keys.base import DecryptionKey, EncryptionKey
from age.recipients.base import Recipient

# import following classes for registration at Recipient.__subclasses__
from age.recipients.scrypt import SCryptRecipient  # noqa: F401
from age.recipients.ssh_ed25519 import SSHED25519Recipient  # noqa: F401
from age.recipients.ssh_rsa import SSHRSARecipient  # noqa: F401
from age.recipients.x25519 import X25519Recipient  # noqa: F401


def _filter_keys_for_recipient(recipient: Recipient, keys: typing.Collection[DecryptionKey]):
    return set(k for k in keys if isinstance(k, recipient.DECRYPTION_KEY_TYPE))


def decrypt_file_key(
    recipients: typing.Collection[Recipient], keys: typing.Collection[DecryptionKey]
) -> bytes:
    for recipient in recipients:
        for key in _filter_keys_for_recipient(recipient, keys):
            try:
                return recipient.decrypt(key)
            except InvalidTag:
                continue

    raise NoIdentity("No matching key")


def get_recipient(type: str, arguments: typing.List[str], body: str) -> Recipient:
    for subclass in Recipient.__subclasses__():
        if subclass.TAG == type:
            return subclass.load(arguments, body)

    raise UnknownRecipient("Cannot parse recipient line: Unknown recipient type")


def generate_recipient_from_key(key: EncryptionKey, file_key: bytes) -> Recipient:
    for subclass in Recipient.__subclasses__():
        if isinstance(key, subclass.ENCRYPTION_KEY_TYPE):
            return subclass.generate(key, file_key)

    raise UnknownRecipient("Cannot generate recipient: Unknown encryption key type")
