import typing

from cryptography.exceptions import InvalidTag

from age.primitives import (
    encode,
    decode,
    random,
    hkdf,
    encrypt,
    decrypt,
    hmac_generate,
    hmac_verify,
    x25519,
    CURVE_25519_BASEPOINT,
    scrypt,
    rsa_encrypt,
    sha256,
)
from age.structure import AgeFile, AgeRecipient
from age.algorithms import (
    x25519_decrypt_file_key,
    scrypt_decrypt_file_key,
    x25519_encrypt_file_key,
    scrypt_encrypt_file_key,
)
from age.keys import AgePrivateKey, AgePublicKey, PasswordKey
from age.keys.base import EncryptionKey, DecryptionKey
from age.stream import stream_decrypt


class NoMatchingKey(Exception):
    pass


def match_key_recipient(
    recipients: typing.Collection[AgeRecipient],
    keys: typing.Collection[DecryptionKey],
) -> bytes:
    def filter_keys(type_: type):
        return filter(lambda k: isinstance(k, type_), keys)

    for recipient in recipients:
        if recipient.type_ == AgeRecipient.Type.X25519:
            for key in filter_keys(AgePrivateKey):
                try:
                    return x25519_decrypt_file_key(key, *recipient.arguments)
                except InvalidTag:
                    continue

        elif recipient.type_ == AgeRecipient.Type.SCRYPT:
            for key in filter_keys(PasswordKey):
                try:
                    return scrypt_decrypt_file_key(key, *recipient.arguments)
                except InvalidTag:
                    continue

    raise NoMatchingKey


def authenticate_header(
    header: bytes, file_key: bytes, authentication_tag: bytes
):
    key = hkdf(b"", b"header")(file_key, 32)
    return hmac_verify(key, header)(authentication_tag)


def decrypt_file(
    age_file: AgeFile, keys: typing.Collection[DecryptionKey]
) -> bytes:

    file_key = match_key_recipient(age_file.recipients, keys)
    authenticate_header(
        age_file.authenticated_header, file_key, age_file.authentication_tag
    )

    nonce = age_file.body[:16]
    ciphertext = age_file.body[16:]

    key = hkdf(nonce, b"payload")(file_key, 32)
    plaintext = stream_decrypt(key, ciphertext)
    return plaintext


def generate_recipient(key: EncryptionKey, file_key: bytes) -> AgeRecipient:
    if isinstance(key, AgePublicKey):
        _, *arguments = x25519_encrypt_file_key(key, file_key)
        return AgeRecipient(AgeRecipient.Type.X25519, arguments)
    elif isinstance(key, PasswordKey):
        _, *arguments = scrypt_encrypt_file_key(key, file_key)
        return AgeRecipient(AgeRecipient.Type.SCRYPT, arguments)


def encrypt_body(file_key, data):
    nonce = random(16)
    key = hkdf(nonce, b"payload")(file_key, 32)


def ssh_rsa_recipient(ssh_key, file_key):
    fingerprint = sha256(ssh_key)[:4]
    label = "age-tool.com ssh-rsa"
    encrypted = rsa_encrypt(ssh_key, label)(file_key)
    return f"-> ssh-rsa {encode(fingerprint)} {encode(encrypted)}"
