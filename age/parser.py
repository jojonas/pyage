import io
import re
import sys
import typing

from age.primitives import decode
from age.header import EncryptionAlgorithm, PreliminaryHeader
from age.recipients import parse_recipient_line

__all__ = ["parse_bytes", "parse_file"]

FILE_SIGNATURE_RE = re.compile(
    rb"This is a file encrypted with age-tool\.com, version (\d+)"
)


def parse_bytes(data: bytes) -> typing.Tuple[PreliminaryHeader, bytes]:
    # I know this parser is a mess!

    # But so far there are some inconsistencies in Filippo's age spec
    # (concerning the wrapping of encode() and the separation of argument)
    # So it doesn't yet make sense to implement a proper parser.
    # Once the spec is solid, one could use something like parsimonious
    # (https://github.com/erikrose/parsimonious/).

    stream = io.BytesIO(data)
    header = PreliminaryHeader()

    first_line = stream.readline()[:-1]
    match = FILE_SIGNATURE_RE.match(first_line)
    if not match:
        raise ValueError("Age file signature not found.")

    # this is not officially defined to be an int...
    header.age_version = int(match.group(1).decode("ascii"))

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
    _, encryption_algorithm_name, encoded_authentication_tag = line.split()

    assert encryption_algorithm_name == "ChaChaPoly"
    header.encryption_algorithm = EncryptionAlgorithm(
        encryption_algorithm_name
    )

    header.authentication_tag = decode(encoded_authentication_tag)

    # header (for authentication) is the entire header up to AEAD (= ChaChaPoly) included
    search = b"\n--- ChaChaPoly"
    index = data.index(search) + len(search)
    header.data_to_authenticate = data[:index]

    for line in joined_lines:
        try:
            recipient = parse_recipient_line(line)
        except ValueError:
            # unknown recipient type, ignore
            print(
                f"Ignoring unknown recipient type in line: {line}",
                file=sys.stderr,
            )
        header.recipients.append(recipient)

    body = stream.read()

    return header, body


def parse_file(file: typing.Union[str, typing.BinaryIO]):
    if isinstance(file, str):
        with open(file, "rb") as f:
            data = f.read()
    else:
        data = file.read()

    return parse_bytes(data)
