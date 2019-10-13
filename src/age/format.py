import io
import typing

from age.exceptions import ParserError
from age.primitives.encode import decode, encode

__all__ = ["Recipient", "Header", "load_header", "dump_header"]


class Recipient:
    def __init__(self, type: str = "", arguments: typing.List[str] = None, body: str = ""):
        if arguments is None:
            arguments = []

        self.type: str = type
        self.arguments: typing.List[str] = arguments
        self.body: str = body


class Header:
    def __init__(self, recipients: typing.List[Recipient] = None):
        if recipients is None:
            recipients = []

        self.recipients: typing.List[Recipient] = recipients


MAGIC = "This is a file encrypted with age-tool.com, version 1"
RECIPIENT_PREFIX = "->"
FOOTER_PREFIX = "---"
AEAD = "ChaChaPoly"


def load_header(stream: typing.BinaryIO) -> typing.Tuple[Header, bytes]:
    first_line = stream.readline().strip()

    if first_line.decode("utf-8", "replace") != MAGIC:
        raise ParserError("File signature not found.")

    header = Header()

    for raw_line in stream:
        line = raw_line.decode("utf-8")

        if line.startswith(RECIPIENT_PREFIX):
            type, *args = line[len(RECIPIENT_PREFIX) :].split()
            header.recipients.append(Recipient(type, args))
        elif line.startswith(FOOTER_PREFIX):
            break
        elif len(header.recipients) > 0:
            header.recipients[-1].body += line.replace("\n", "")

    assert line.startswith(FOOTER_PREFIX)
    _, aead, encoded_mac = line.split()
    assert aead == AEAD
    mac = decode(encoded_mac)

    return header, mac


def dump_header(header: Header, stream: typing.BinaryIO, mac: bytes = None):
    stream.write(MAGIC.encode("utf-8") + b"\n")

    for recipient in header.recipients:
        line = RECIPIENT_PREFIX + " " + recipient.type + " " + " ".join(recipient.arguments) + "\n"
        stream.write(line.encode("utf-8"))
        if recipient.body:
            stream.write(recipient.body.encode("utf-8") + b"\n")

    footer = FOOTER_PREFIX + " " + AEAD
    if mac:
        footer += " " + encode(mac)

    stream.write(footer.encode("utf-8"))