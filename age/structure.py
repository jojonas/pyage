import enum
import typing

__all__ = ["AgeRecipient", "AgeAuthenticationTag", "AgeFile"]


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


class AgeAuthenticationTag:
    @enum.unique
    class Type(enum.Enum):
        CHACHAPOLY = "ChaChaPoly"

    def __init__(self, type_: Type, value: bytes):
        self.type_: AgeAuthenticationTag.Type = type_
        self.value: bytes = value


class AgeFile:
    def __init__(
        self,
        age_version: int,
        recipients: typing.Collection[AgeRecipient],
        authentication_tag: AgeAuthenticationTag,
        encrypted_data: bytes,
    ):
        self.age_version: int = age_version
        self.recipients: typing.Collection[AgeRecipient] = recipients
        self.authentication_tag: AgeAuthenticationTag = authentication_tag
        self.encrypted_data: bytes = encrypted_data
