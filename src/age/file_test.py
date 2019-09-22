import io

from pytest import raises

from age.file import EncryptionAlgorithm, LockedFile
from age.keys.password import PasswordKey
from age.recipients.x25519 import X25519Recipient

# This is almost the test file from age-tool.com (18.09.2019).
# However, I modified the lines to include spaces between the arguments.
# Unfortunately Filippos original intention is not clear from the Google
# doc as Google docs seems to reduce multiple trailing spaces into one.
GOOGLE_DOC_TEST_FILE = b"""This is a file encrypted with age-tool.com, version 1
-> X25519 CJM36AHmTbdHSuOQL-NESqyVQE75f2e610iRdLPEN20
 C3ZAeY64NXS4QFrksLm3EGz-uPRyI0eQsWw7LWbbYig
-> X25519 ytazqsbmUnPwVWMVx0c1X9iUtGdY4yAB08UQTY2hNCI
 N3pgrXkbIn_RrVt0T0G3sQr1wGWuclqKxTSWHSqGdkc
-> scrypt bBjlhJVYZeE4aqUdmtRHfw 32768
 ZV_AhotwSGqaPCU43cepl4WYUouAa17a3xpu4G2yi5k
-> invalid IGNOREME
-> ssh-rsa mhir0Q
 xD7o4VEOu1t7KZQ1gDgq2FPzBEeSRqbnqvQEXdLRYy143BxR6oFxsUUJC
RB0ErXAmgmZq7tIm5ZyY89OmqZztOgG2tEB1TZvX3Q8oXESBuFjBBQkKa
MLkaqh5GjcGRrZe5MmTXRdEyNPRl8qpystNZR1q2rEDUHSEJInVLW8Otv
QRG8P303VpjnOUU53FSBwyXxDtzxKxeloceFubn_HWGcR0mHU-1e9l39m
yQEUZjIoqFIELXvh9o6RUgYzaAI-m_uPLMQdlIkiOOdbsrE6tFesRLZNH
AYspeRKI9MJ--Xg9i7rutU34ZM-1BL6KgZfJ9FSm-GFHiVWpr1MfYCo_w
-> ssh-ed25519 BjH7FA RO-wV4kbbl4NtSmp56lQcfRdRp3dEFpdQmWkaoiw6lY
 51eEu5Oo2JYAG7OU4oamH03FDRP18_GnzeCrY7Z-sa8
--- ChaChaPoly fgMiVLJHMlg9fW7CVG+hPS5EAU4Zeg19LyCP7SoH5nA
[BINARY ENCRYPTED PAYLOAD]"""

# encrypted with password 'secret'
OWN_TEST_FILE = b"""This is a file encrypted with age-tool.com, version 1
-> scrypt 2uD24mjsdA5ueg5-jb-MfA13kg 32768 M6r7ldIulCdnYKj6SeFWPZhgbPACWUP4BiS58igRAvM
--- ChaChaPoly 9GY-9MErVMdqmgQAuKhZJUsZ7bsJyqZZUnh2npvcoXM
)R)\x04\xae\xa9/\xab\xcf\x1c\x8a\x8d\xceR\xcc\x8f\xaa#\x08\x81P\x01\xcc\xef?+\x1b\xb4\xee\xb2\xdb>m9\xbf\xdeJ\\\xf9\xdd\xd2;\xd0\xff\xf0Z_Z"""


def test_parse_google_doc_test_file():
    stream = io.BytesIO(GOOGLE_DOC_TEST_FILE)

    locked_file = LockedFile.from_file(stream)

    assert locked_file.age_version == 1
    assert len(set(locked_file.recipients)) == 5
    assert isinstance(locked_file.recipients[0], X25519Recipient)
    assert locked_file.encryption_algorithm == EncryptionAlgorithm.CHACHAPOLY
    assert stream.read() == b"[BINARY ENCRYPTED PAYLOAD]"

    stream = io.BytesIO(b"This is a file encrypted with something else, version 5\n")
    with raises(ValueError):
        LockedFile.from_file(stream)


def test_parse_own_test_file():
    stream = io.BytesIO(OWN_TEST_FILE)

    locked_file = LockedFile.from_file(stream)
    key = PasswordKey(b"secret")

    age_file = locked_file.unlock([key])
    assert age_file is not None

    assert len(age_file.recipients) == 1
    assert len(age_file.file_key) == 16

    with raises(AttributeError):
        # recipients should be read-only
        age_file.recipients = []

    with raises(AttributeError):
        # file_key should be read-only
        age_file.file_key = b"foobar"

    cipherstream = io.BytesIO(
        b")R)\x04\xae\xa9/\xab\xcf\x1c\x8a\x8d\xceR\xcc\x8f\xaa#\x08\x81P\x01\xcc\xef?+\x1b\xb4\xee\xb2\xdb>m9\xbf\xdeJ\\\xf9\xdd\xd2;\xd0\xff\xf0Z_Z"
    )
    plainstream = io.BytesIO()
    age_file.decrypt(cipherstream, plainstream)
    plainstream.seek(0)
    assert plainstream.read() == b"Hello Password!\n"

    plainstream = io.BytesIO(b"Hello World!\n")
    cipherstream = io.BytesIO()
    age_file.encrypt(plainstream, cipherstream)
    cipherstream.seek(0)
    assert len(cipherstream.read()) > 0

    headerstream = io.BytesIO()
    age_file.serialize_header(headerstream)
    headerstream.seek(0)
    assert (
        headerstream.read()
        == b"""This is a file encrypted with age-tool.com, version 1
-> scrypt 2uD24mjsdA5ueg5-jb-MfA13kg 32768 M6r7ldIulCdnYKj6SeFWPZhgbPACWUP4BiS58igRAvM
--- ChaChaPoly 9GY-9MErVMdqmgQAuKhZJUsZ7bsJyqZZUnh2npvcoXM
"""
    )
