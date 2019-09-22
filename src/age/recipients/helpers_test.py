import os

from pytest import raises

from age.keys.agekey import AgePrivateKey
from age.keys.base import EncryptionKey
from age.recipients.helpers import (
    decrypt_file_key,
    generate_recipient_from_key,
    parse_recipient_line,
)
from age.recipients.x25519 import X25519Recipient


def test_decrypt_file_key():
    file_key = os.urandom(16)

    private_key = AgePrivateKey.generate()

    recipients = [X25519Recipient.generate(private_key.public_key(), file_key)]

    assert decrypt_file_key(recipients, [private_key]) == file_key

    with raises(ValueError):
        decrypt_file_key(recipients, [])

    with raises(ValueError):
        decrypt_file_key(recipients, [AgePrivateKey.generate()])


def test_recipient_line_parsing():
    LINE = "-> X25519 r8_wQqHknnD7kpTtyt2MHlMFflGplYR-IDtV3mRuaAE QP2nUlmkrAjvRJXIo1WHS9dyDBuoZa3RPxVOUB3cNfs"
    recipient = parse_recipient_line(LINE)

    assert isinstance(recipient, X25519Recipient)

    with raises(ValueError):
        parse_recipient_line("-> INVALIDLINE xxx")


def test_recipient_from_key():
    file_key = os.urandom(16)
    public_key = AgePrivateKey.generate().public_key()

    recipient = generate_recipient_from_key(public_key, file_key)
    assert isinstance(recipient, X25519Recipient)

    with raises(ValueError):
        generate_recipient_from_key(EncryptionKey(), file_key)
