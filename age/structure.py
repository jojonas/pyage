import enum
import typing

__all__ = ["AgeRecipient", "AgeFile", "EncryptionAlgorithm"]


class AgeRecipient:
    @enum.unique
    class Type(enum.Enum):
        X25519 = "X25519"
        SCRYPT = "scrypt"
        SSH_RSA = "ssh-rsa"
        SSH_ED25519 = "ssh-ed25519"

    def __init__(self, type_: Type, arguments: typing.Collection[str] = None):
        self.type_: AgeRecipient.Type = type_
        self.arguments: typing.Collection[str] = arguments if arguments else []


@enum.unique
class EncryptionAlgorithm(enum.Enum):
    CHACHAPOLY = "ChaChaPoly"


class AgeFile:
    def __init__(
        self,
        age_version: int,
        recipients: typing.Collection[AgeRecipient],
        encryption_algorithm: EncryptionAlgorithm,
        authentication_tag: bytes,
        authenticated_header: bytes,
        body: bytes,
    ):
        self.age_version: int = age_version

        self.recipients: typing.Collection[AgeRecipient] = recipients

        self.encryption_algorithm: EncryptionAlgorithm = encryption_algorithm
        self.authentication_tag: bytes = authentication_tag
        self.authenticated_header: bytes = authenticated_header

        self.body: bytes = body
