import io
import sys
import typing

from age.exceptions import UnknownRecipient
from age.format import Header, Recipient, dump_header, load_header
from age.keys.base import DecryptionKey, EncryptionKey
from age.primitives.hkdf import hkdf
from age.primitives.hmac import HMAC
from age.primitives.random import random
from age.recipients.helpers import decrypt_file_key, generate_recipient_from_key, get_recipient
from age.stream import stream_decrypt, stream_encrypt

__all__ = ["Encryptor", "Decryptor"]

HEADER_HKDF_LABEL = b"header"
PAYLOAD_HKDF_LABEL = b"payload"


class Encryptor(io.RawIOBase):
    def __init__(self, keys: typing.Collection[EncryptionKey], stream: typing.BinaryIO):
        self._stream: typing.BinaryIO = stream
        self._file_key: bytes = random(16)

        self._plaintext_buffer: bytes = b""

        self._write_header(keys)

    def writable(self):
        return True

    def write(self, data):
        self._plaintext_buffer += data
        return len(data)

    def close(self):
        if not self.closed:
            self._encrypt_buffer()
            super().close()

    def _hkdf(self, label: bytes, salt: bytes = b"") -> bytes:
        return hkdf(salt, label, self._file_key, 32)

    def _write_header(self, keys):
        header = Header()

        for key in keys:
            recipient = generate_recipient_from_key(key, self._file_key)
            recipient_args, recipient_body = recipient.dump()
            header.recipients.append(Recipient(recipient.TAG, recipient_args, recipient_body))

        header_stream = io.BytesIO()
        dump_header(header, header_stream, mac=None)

        mac = HMAC(self._hkdf(HEADER_HKDF_LABEL)).generate(header_stream.getvalue())
        dump_header(header, self._stream, mac=mac)

    def _encrypt_buffer(self):
        self._stream.write(b"\n")

        nonce = random(16)
        self._stream.write(nonce)

        stream_key = self._hkdf(PAYLOAD_HKDF_LABEL, nonce)
        ciphertext = stream_encrypt(stream_key, self._plaintext_buffer)
        self._stream.write(ciphertext)

        self._plaintext_buffer = b""


class Decryptor(io.RawIOBase):
    def __init__(self, identities: typing.Collection[DecryptionKey], stream: typing.BinaryIO):
        self._stream: typing.BinaryIO = stream
        self._file_key: typing.Optional[bytes] = None
        self._plaintext_stream: typing.Optional[typing.BinaryIO] = None

        self._decrypt_header(identities)
        self._decrypt_body()

    def readable(self):
        return True

    def read(self, size=-1):
        assert self._plaintext_stream is not None
        return self._plaintext_stream.read(size)

    def _hkdf(self, label: bytes, salt: bytes = b"") -> bytes:
        assert self._file_key is not None
        return hkdf(salt, label, self._file_key, 32)

    def _decrypt_header(self, identities: typing.Collection[DecryptionKey]):
        header, mac = load_header(self._stream)

        recipients = []
        for header_recipient in header.recipients:
            try:
                recipient = get_recipient(
                    header_recipient.type, header_recipient.arguments, header_recipient.body
                )
            except UnknownRecipient:
                print(f"Ignoring unknown recipient type '{header_recipient.type}'", file=sys.stderr)
            else:
                recipients.append(recipient)

        self._file_key = decrypt_file_key(recipients, identities)
        header_stream = io.BytesIO()
        dump_header(header, header_stream, mac=None)
        HMAC(self._hkdf(HEADER_HKDF_LABEL)).verify(header_stream.getvalue(), mac)
        # TODO: Should we try another identity if HMAC validation fails?

    def _decrypt_body(self):
        assert self._file_key is not None

        nonce = self._stream.read(16)
        assert len(nonce) == 16, "Could not read nonce"

        stream_key = self._hkdf(PAYLOAD_HKDF_LABEL, nonce)
        ciphertext = self._stream.read()
        plaintext = stream_decrypt(stream_key, ciphertext)

        self._plaintext_stream = io.BytesIO(plaintext)
        self._plaintext_stream.seek(0)
