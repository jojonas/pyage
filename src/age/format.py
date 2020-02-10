import textwrap
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


AGE_INTRO = "age-encryption.org/v1"
RECIPIENT_PREFIX = "->"
FOOTER_PREFIX = "---"
AEAD = "ChaChaPoly"


def load_header(stream: typing.BinaryIO) -> typing.Tuple[Header, bytes]:
    first_line = stream.readline().strip()

    if first_line.decode("utf-8", "replace") != AGE_INTRO:
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
            header.recipients[-1].body += line.strip()

    assert line.startswith(FOOTER_PREFIX)
    prefix, encoded_mac = line.split()
    assert prefix == FOOTER_PREFIX
    mac = decode(encoded_mac)

    return header, mac


def dump_header(header: Header, stream: typing.BinaryIO, mac: bytes = None):
    stream.write(AGE_INTRO.encode("utf-8") + b"\n")

    for recipient in header.recipients:
        line = RECIPIENT_PREFIX + " " + recipient.type + " " + " ".join(recipient.arguments) + "\n"
        stream.write(line.encode("utf-8"))
        if recipient.body:
            wrapped = textwrap.fill(recipient.body, break_on_hyphens=False, width=64)
            stream.write(wrapped.encode("utf-8") + b"\n")

    footer = FOOTER_PREFIX
    if mac:
        footer += " " + encode(mac)

    stream.write(footer.encode("utf-8"))
