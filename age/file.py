import collections
import enum
import io
import re
import sys
import typing

from age.primitives import encode, random, hkdf, HMAC, decode
from age.keys.base import EncryptionKey, DecryptionKey
from age.recipients import (
    Recipient,
    generate_recipient_from_key,
    decrypt_file_key,
    parse_recipient_line,
)
from age.stream import stream_decrypt, stream_encrypt

__all__ = ["LockedFile", "File", "EncryptionAlgorithm"]

FILE_SIGNATURE_RE = re.compile(
    rb"This is a file encrypted with age-tool\.com, version (\d+)"
)


@enum.unique
class EncryptionAlgorithm(enum.Enum):
    CHACHAPOLY = "ChaChaPoly"


LockedFileBase = collections.namedtuple(
    "LockedFileBase",
    (
        "age_version",
        "recipients",
        "encryption_algorithm",
        "authentication_tag",
        "data_to_authenticate",
    ),
)


class LockedFile(LockedFileBase):
    def unlock(self, keys: typing.Collection[DecryptionKey]):
        file_key = decrypt_file_key(self.recipients, keys)
        self._authenticate(file_key)
        return File(
            file_key=file_key,
            recipients=self.recipients,
            age_version=self.age_version,
            encryption_algorithm=self.encryption_algorithm,
        )

    def _authenticate(self, file_key):
        key = hkdf(b"", b"header", file_key, 32)
        HMAC(key).verify(self.data_to_authenticate, self.authentication_tag)

    @classmethod
    def from_file(cls, stream: typing.BinaryIO):
        # I know this parser is a mess!

        # But so far there are some inconsistencies in Filippo's age spec
        # (concerning the wrapping of encode() and the separation of argument)
        # So it doesn't yet make sense to implement a proper parser.
        # Once the spec is solid, one could use something like parsimonious
        # (https://github.com/erikrose/parsimonious/).

        to_authenticate_buffer = b""

        def read_line():
            nonlocal stream, to_authenticate_buffer

            line = stream.readline()
            to_authenticate_buffer += line
            return line[:-1]

        first_line = read_line()
        match = FILE_SIGNATURE_RE.match(first_line)
        if not match:
            raise ValueError("Age file signature not found.")

        # this is not officially defined to be an int...
        age_version = int(match.group(1).decode("ascii"))

        joined_lines = []

        buffer = ""
        while True:
            line = read_line().decode("utf-8")
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
        encryption_algorithm = EncryptionAlgorithm(encryption_algorithm_name)

        authentication_tag = decode(encoded_authentication_tag)

        # header (for authentication) is the entire header up to AEAD (= ChaChaPoly) included
        search = b"\n--- ChaChaPoly"
        index = to_authenticate_buffer.index(search) + len(search)
        data_to_authenticate = to_authenticate_buffer[:index]

        recipients = []
        for line in joined_lines:
            try:
                recipient = parse_recipient_line(line)
            except ValueError:
                # unknown recipient type, ignore
                print(
                    f"Ignoring unknown recipient type in line: {line}",
                    file=sys.stderr,
                )
                continue

            recipients.append(recipient)

        return cls(
            age_version=age_version,
            recipients=recipients,
            encryption_algorithm=encryption_algorithm,
            authentication_tag=authentication_tag,
            data_to_authenticate=data_to_authenticate,
        )


class File:
    """A (decrypted) age file.

    Assumes that the ``file_key`` has been successfully decrypted."""

    def __init__(
        self,
        file_key: bytes,
        recipients: typing.Collection[Recipient],
        encryption_algorithm: EncryptionAlgorithm,
        age_version: int,
    ):
        self._file_key: bytes = file_key
        self._recipients: typing.List[Recipient] = list(recipients)
        self._encryption_algorithm: EncryptionAlgorithm = encryption_algorithm
        self._age_version: int = age_version

    @classmethod
    def new(cls):
        """Create a new age header.

        Generates a new ``file_key``."""

        return cls(random(16), [], EncryptionAlgorithm.CHACHAPOLY, 1)

    def add_recipient(self, key: EncryptionKey):
        """Add key to the list of recipients"""

        recipient = generate_recipient_from_key(key, self._file_key)
        self._recipients.append(recipient)

    @property
    def recipients(self) -> typing.Collection[Recipient]:
        """Read-only access to the list of recipients"""

        return tuple(self._recipients)

    @property
    def file_key(self) -> bytes:
        """Read-only access to the secret file key"""

        return self._file_key

    def serialize_header(self) -> bytes:
        """Get serialized version of file header"""

        header = self._serialize_until_authentication()
        authentication_tag = self._authentication_tag(header)
        return (
            header + b" " + encode(authentication_tag).encode("ascii") + b"\n"
        )

    def _serialize_until_authentication(self) -> bytes:
        output = f"This is a file encrypted with age-tool.com, version {self._age_version}\n"
        for recipient in self._recipients:
            output += recipient.get_recipient_line() + "\n"
        output += "--- " + self._encryption_algorithm.value
        return output.encode("ascii")

    def _authentication_tag(self, data) -> bytes:
        key = hkdf(b"", b"header", self._file_key, 32)
        return HMAC(key).generate(data)

    def encrypt(
        self,
        plaintext_stream: typing.BinaryIO,
        ciphertext_stream: typing.BinaryIO,
    ) -> int:
        return ciphertext_stream.write(
            self.encrypt_bytes(plaintext_stream.read())
        )

    def decrypt(
        self,
        ciphertext_stream: typing.BinaryIO,
        plaintext_stream: typing.BinaryIO,
    ) -> int:
        return plaintext_stream.write(
            self.decrypt_bytes(ciphertext_stream.read())
        )

    def decrypt_bytes(self, body: bytes) -> bytes:
        """Decrypt age file body bytes using the header's ``file_key``."""

        assert self._encryption_algorithm == EncryptionAlgorithm.CHACHAPOLY

        nonce = body[:16]
        ciphertext = body[16:]

        key = hkdf(nonce, b"payload", self._file_key, 32)
        return stream_decrypt(key, ciphertext)

    def encrypt_bytes(self, data: bytes) -> bytes:
        """Encrypt age file body bytes using the header's ``file_key``."""

        assert self._encryption_algorithm == EncryptionAlgorithm.CHACHAPOLY

        nonce = random(16)
        key = hkdf(nonce, b"payload", self._file_key, 32)
        ciphertext = stream_encrypt(key, data)
        return nonce + ciphertext
