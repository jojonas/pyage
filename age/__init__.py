import typing

from cryptography.exceptions import InvalidTag

from age.primitives import encode, decode, random, hkdf, encrypt, decrypt, \
    hmac, x25519, CURVE_25519_BASEPOINT, scrypt, rsa_encrypt, sha256
from age.structure import AgeRecipient
from age.algorithms import x25519_decrypt_file_key, scrypt_decrypt_file_key
from age.keys import AgePrivateKey


def try_decrypt_file_key(recipients: typing.Collection[AgeRecipient],
                         keys: typing.Collection[typing.Any]) -> bytes:

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
            for key in filter_keys(bytes):
                try:
                    return scrypt_decrypt_file_key(key, *recipient.arguments)
                except InvalidTag:
                    continue


def header_aead(header, file_key):
    key = hkdf("", "header")(file_key, 32)
    mac = hmac(key)(header)
    return f"--- ChaChaPoly {encode(mac)}"


def encrypt_body(file_key, data):
    nonce = random(16)
    key = hkdf(nonce, b"payload")(file_key, 32)


def ssh_rsa_recipient(ssh_key, file_key):
    fingerprint = sha256(ssh_key)[:4]
    label = "age-tool.com ssh-rsa"
    encrypted = rsa_encrypt(ssh_key, label)(file_key)
    return f"-> ssh-rsa {encode(fingerprint)} {encode(encrypted)}"
