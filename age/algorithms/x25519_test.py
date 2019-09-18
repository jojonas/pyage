import os

from age.algorithms.x25519 import X25519Encryption, X25519Decryption
from age.keys import AgePrivateKey


def test_all():
    key = AgePrivateKey.generate()

    file_secret = os.urandom(32)

    encryption = X25519Encryption(key.public_key())

    recipient = encryption.generate_recipient(file_secret)
    print(recipient)

    decryption = X25519Decryption(key)
    decrypted = decryption.parse_recipient(recipient)

    assert decrypted == file_secret
