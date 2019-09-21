import io

from age.file import LockedFile, EncryptionAlgorithm
from age.recipients import X25519Recipient

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


def test_parse_google_doc_test_file():
    stream = io.BytesIO(GOOGLE_DOC_TEST_FILE)

    locked_file = LockedFile.from_file(stream)

    assert locked_file.age_version == 1
    assert len(set(locked_file.recipients)) == 5
    assert isinstance(locked_file.recipients[0], X25519Recipient)
    assert locked_file.encryption_algorithm == EncryptionAlgorithm.CHACHAPOLY
    assert stream.read() == b"[BINARY ENCRYPTED PAYLOAD]"
