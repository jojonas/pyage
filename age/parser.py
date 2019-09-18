import io
import re
import typing

from age.primitives import decode
from age.structure import AgeFile, AgeRecipient, AgeAuthenticationTag

__all__ = ['parse_bytes', 'parse_file']

FILE_SIGNATURE_RE = re.compile(
    rb"This is a file encrypted with age-tool\.com, version (\d+)")


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

    # this is not officially defined to be an int...
    age_version = int(match.group(1).decode("ascii"))

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
    _, aead_type_name, encoded_aead_value = line.split()
    aead_type = AgeAuthenticationTag.Type(aead_type_name)
    aead_value = decode(encoded_aead_value)

    recipients = []
    for line in joined_lines:
        _, type_name, *arguments = line.split()

        try:
            type_ = AgeRecipient.Type(type_name)
        except ValueError:
            # unknown recipient type, ignore
            continue
        recipients.append(AgeRecipient(type_, arguments=arguments))

    return AgeFile(
        age_version=age_version,
        recipients=recipients,
        authentication_tag=AgeAuthenticationTag(aead_type, aead_value),
        encrypted_data=stream.read()
    )


def parse_file(file: typing.Union[str, typing.BinaryIO]):
    if isinstance(file, str):
        with open(file, 'rb') as f:
            data = f.read()
    else:
        data = file.read()

    return parse_bytes(data)
