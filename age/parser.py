import enum
import io
import re
import typing

from age.primitives import decode

__all__ = ['RecipientType', 'Recipient', 'AEADTag',
           'AgeFile', 'parse_bytes', 'parse_file']

FILE_SIGNATURE_RE = re.compile(
    rb"This is a file encrypted with age-tool.com, version (\d+)")


class RecipientType(enum.Enum):
    X25519 = "X25519"
    SCRYPT = "scrypt"
    SSH_RSA = "ssh-rsa"
    SSH_ED25519 = "ssh-ed25519"


class Recipient:
    def __init__(self, type_: RecipientType,
                 arguments: typing.List[str] = None):
        self.type_: RecipientType = type_
        self.arguments: typing.List[str] = arguments if arguments else []


class AEADTag:
    def __init__(self, type_: str, value: bytes):
        self.type_: str = type_
        self.value: bytes = value


class AgeFile:
    def __init__(self, age_version: str, recipients: typing.List[Recipient],
                 aead_tag: AEADTag, encrypted_data: bytes):
        self.age_version: str = age_version
        self.recipients: typing.List[Recipient] = recipients
        self.aead_tag: AEADTag = aead_tag
        self.encrypted_data: bytes = encrypted_data


def parse_bytes(data: bytes) -> AgeFile:
    # I know this parser is a mess!

    # But so far there are some inconsistencies in Filippo's age spec
    # (concerning the wrapping of encode() and the separation of argument)
    # So it doesn't yet make sense to implement a proper parser.
    # Once the spec is solid, one could use something like parsimonious
    # (https://github.com/erikrose/parsimonious/).

    stream = io.BytesIO(data)

    first_line = stream.readline()[:-1]
    match = FILE_SIGNATURE_RE.match(first_line)
    if not match:
        raise ValueError("Age file signature not found.")

    age_version = match.group(1).decode("ascii")

    joined_lines = []

    buffer = ""
    while True:
        line = stream.readline()[:-1].decode("utf-8")
        if line.startswith("-> "):
            if buffer:
                joined_lines.append(buffer)
                buffer = ""
            buffer = line
        elif line.startswith("--- "):
            break
        else:
            buffer += line
    joined_lines.append(buffer)

    assert line.startswith("--- ")
    _, aead_type, aead_tag = line.split()
    aead_value = decode(aead_tag)

    recipients = []
    for line in joined_lines:
        _, type_name, *arguments = line.split()
        type_ = RecipientType(type_name)
        recipients.append(Recipient(type_, arguments=arguments))

    return AgeFile(
        age_version=age_version,
        recipients=recipients,
        aead_tag=AEADTag(aead_type, aead_value),
        encrypted_data=stream.read()
    )


def parse_file(file: typing.Union[str, typing.BinaryIO]):
    if isinstance(file, str):
        with open(file, 'rb') as f:
            data = f.read()
    else:
        data = file.read()

    return parse_bytes(data)
