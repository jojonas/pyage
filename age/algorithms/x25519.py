import typing

from age.primitives import (
    encode,
    decode,
    random,
    hkdf,
    encrypt,
    decrypt,
    x25519,
    CURVE_25519_BASEPOINT,
)

from age.keys import AgePublicKey, AgePrivateKey

__all__ = [
    "x25519_encrypt_file_key",
    "x25519_decrypt_file_key",
    "X25519_RECIPIENT_LABEL",
]

X25519_RECIPIENT_LABEL = "X25519"
AGE_X25519_HKDF_LABEL = b"age-tool.com X25519"


def x25519_encrypt_file_key(
    public_key: AgePublicKey, file_key: bytes
) -> typing.Tuple[str, str, str]:
    ephemeral_secret = random(32)
    public_key_bytes = public_key.public_bytes()

    salt = x25519(ephemeral_secret, CURVE_25519_BASEPOINT) + public_key_bytes

    derived_secret = x25519(ephemeral_secret, CURVE_25519_BASEPOINT)
    key_material = x25519(ephemeral_secret, public_key_bytes)

    key = hkdf(salt, AGE_X25519_HKDF_LABEL)(key_material, 32)
    encrypted = encrypt(key)(file_key)

    return X25519_RECIPIENT_LABEL, encode(derived_secret), encode(encrypted)


def x25519_decrypt_file_key(
    private_key: AgePrivateKey, derived_secret: str, encrypted: str
):
    derived_secret_bytes = decode(derived_secret)
    encrypted_bytes = decode(encrypted)

    private_key_bytes = private_key.private_bytes()
    public_key_bytes = private_key.public_key().public_bytes()

    salt = derived_secret_bytes + public_key_bytes

    # Public and private keys in are related as follows:
    # public_key = x25519(private_key, 9)
    # '9' is the curve 25519 base point.

    # Additionally, X25519 has the following property
    # (used e.g. during Diffie-Hellman key exchange):
    # x25519(a, x25519(b, 9)) = x25519(b, x25519(a, 9))

    # During encryption we calculated key_material as:
    # => x25519(ephemeral_secret, public_key)

    # This is therefore equivalent to:
    #  = x25519(ephemeral_secret, x25519(private_key, 9))
    #  = x25519(private_key, x25519(ephemeral_secret, 9))
    #  = x25519(private_key, derived_secret)
    key_material = x25519(private_key_bytes, derived_secret_bytes)

    key = hkdf(salt, AGE_X25519_HKDF_LABEL)(key_material, 32)

    return decrypt(key)(encrypted_bytes)
