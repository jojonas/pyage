import io
import os

import pytest

from age.utils.asciiarmor import read_ascii_armored, write_ascii_armored

TEST_DOCUMENT = """
This is just some garbage...
-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAuv7uWD/IvYMthlNi
LhuVL3aroVV6k5AytAIkdwZuVntEsQLOGrd2Po2UO1yJ9tR/0zUWRFZJUDSiR5ap
RiiTPwIDAQABAkBWV+JMI1+YihqaPKRH7/qJyPzk6OhJfLq8vYSC5RhLm6ODI9Q9
UsfLZCSWGC1+KHpHuovjfmFyJKYqT3qHobnxAiEA3LkVkPxj6rn1koV7lEEywk2x
GCzHtEv4DKJ2fA67XwcCIQDY4eUJvb/2xNznJ0ISlGkh7aozL1oXB56n153L65Dk
CQIhAL/OWu5mVZGpzbxpIM3hpnFxQD8I0vZbug+Isrv1tV/LAiAB5/pbW4+UW6aV
YYLzJtrFsZENYh0olqiOURbR9AASAQIgOaYsSJhYk/bGDYBmcSiSP1Fzv11C4aaJ
jUVZe0IqAVg=
-----END PRIVATE KEY-----
No, this private key is not used for anything besides this test.
I generated it with
$ openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:512
"""


def test_parse_private_key():
    file = io.StringIO(TEST_DOCUMENT)
    data = b""

    for label, data in read_ascii_armored(file):
        assert label == "PRIVATE KEY"

    assert data


def test_roundtrip():
    label = "TEST DATA"

    data = os.urandom(1024)
    outfile = io.StringIO()

    write_ascii_armored(outfile, label, data)
    outfile.seek(0)
    print(outfile.read())
    outfile.seek(0)

    for gotlabel, gotdata in read_ascii_armored(outfile):
        assert gotlabel == label
        assert gotdata == data


def test_invalid():
    with pytest.raises(ValueError):
        for _ in read_ascii_armored(
            io.StringIO(
                """-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAuv7uWD/IvYMthlNi
LhuVL3aroVV6k5AytAIkdwZuVntEsQLOGrd2Po2UO1yJ9tR/0zUWRFZJUDSiR5ap
RiiTPwIDAQABAkBWV+JMI1+YihqaPKRH7/qJyPzk6OhJfLq8vYSC5RhLm6ODI9Q9
UsfLZCSWGC1+KHpHuovjfmFyJKYqT3qHobnxAiEA3LkVkPxj6rn1koV7lEEywk2x
GCzHtEv4DKJ2fA67XwcCIQDY4eUJvb/2xNznJ0ISlGkh7aozL1oXB56n153L65Dk
CQIhAL/OWu5mVZGpzbxpIM3hpnFxQD8I0vZbug+Isrv1tV/LAiAB5/pbW4+UW6aV
YYLzJtrFsZENYh0olqiOURbR9AASAQIgOaYsSJhYk/bGDYBmcSiSP1Fzv11C4aaJ
jUVZe0IqAVg=
-----END PUBLIC KEY-----"""
            )
        ):
            pass

    with pytest.raises(ValueError):
        for _ in read_ascii_armored(
            io.StringIO(
                """-----BEGIN private key-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAuv7uWD/IvYMthlNi
LhuVL3aroVV6k5AytAIkdwZuVntEsQLOGrd2Po2UO1yJ9tR/0zUWRFZJUDSiR5ap
RiiTPwIDAQABAkBWV+JMI1+YihqaPKRH7/qJyPzk6OhJfLq8vYSC5RhLm6ODI9Q9
UsfLZCSWGC1+KHpHuovjfmFyJKYqT3qHobnxAiEA3LkVkPxj6rn1koV7lEEywk2x
GCzHtEv4DKJ2fA67XwcCIQDY4eUJvb/2xNznJ0ISlGkh7aozL1oXB56n153L65Dk
CQIhAL/OWu5mVZGpzbxpIM3hpnFxQD8I0vZbug+Isrv1tV/LAiAB5/pbW4+UW6aV
YYLzJtrFsZENYh0olqiOURbR9AASAQIgOaYsSJhYk/bGDYBmcSiSP1Fzv11C4aaJ
jUVZe0IqAVg=
-----END private key-----"""
            )
        ):
            pass

    with pytest.raises(ValueError):
        for _ in read_ascii_armored(
            io.StringIO(
                """-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAuv7uWD/IvYMthlNiiii
LhuVL3aroVV6k5AytAIkdwZuVntEsQLOGrd2Po2UO1yJ9tR/0zUWRFZJUDSiR5ap
RiiTPwIDAQABAkBWV+JMI1+YihqaPKRH7/qJyPzk6OhJfLq8vYSC5RhLm6ODI9Q9
UsfLZCSWGC1+KHpHuovjfmFyJKYqT3qHobnxAiEA3LkVkPxj6rn1koV7lEEywk2x
GCzHtEv4DKJ2fA67XwcCIQDY4eUJvb/2xNznJ0ISlGkh7aozL1oXB56n153L65Dk
CQIhAL/OWu5mVZGpzbxpIM3hpnFxQD8I0vZbug+Isrv1tV/LAiAB5/pbW4+UW6aV
YYLzJtrFsZENYh0olqiOURbR9AASAQIgOaYsSJhYk/bGDYBmcSiSP1Fzv11C4aaJ
jUVZe0IqAVg=
-----END PRIVATE KEY-----"""
            )
        ):
            pass
