import typing

from age.keys.agekey import AgePrivateKey, AgePublicKey
from age.primitives.encrypt import decrypt, encrypt
from age.primitives.hkdf import hkdf
from age.primitives.random import random
from age.primitives.x25519 import ECPoint, ECScalar, x25519_scalarmult, x25519_scalarmult_base

__all__ = ["x25519_encrypt_file_key", "x25519_decrypt_file_key"]

AGE_X25519_HKDF_LABEL = b"age-encryption.org/v1/X25519"


def x25519_encrypt_file_key(
    public_key: AgePublicKey, file_key: bytes
) -> typing.Tuple[ECPoint, bytes]:
    """Encrypt ``file_key`` with ``public_key``

    From the specification from `age-encryption.org/v1 <https://age-encryption.org/v1>`_ : ::

        -> X25519 encode(X25519(ephemeral secret, basepoint))
            encode(encrypt[HKDF[salt, label](X25519(ephemeral secret, public key), 32)](file key))

    where ``ephemeral secret`` is :func:`age.primitives.random` (32) and MUST be new for every new file key,
    ``salt`` is :func:`age.primitives.X25519` (``ephemeral secret``, ``basepoint``) || ``public key``,
    and ``label`` is ``b"age-encryption.org/v1/X25519"``.

    :returns: ``derived_secret``, ``encrypted_file_key``
    """
    ephemeral_secret = ECScalar(random(32))
    public_key_bytes = public_key.public_bytes()

    derived_secret = x25519_scalarmult_base(ephemeral_secret)
    salt = derived_secret + public_key_bytes

    key_material = x25519_scalarmult(ephemeral_secret, public_key_bytes)
    key = hkdf(salt, AGE_X25519_HKDF_LABEL, key_material, 32)

    encrypted_file_key = encrypt(key, file_key)

    return derived_secret, encrypted_file_key


def _x25519_decrypt_file_key2(
    private_key: AgePrivateKey, derived_secret: ECPoint, encrypted_file_key: bytes, salt: bytes
):
    private_key_bytes = private_key.private_bytes()

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
    key_material = x25519_scalarmult(private_key_bytes, derived_secret)
    key = hkdf(salt, AGE_X25519_HKDF_LABEL, key_material, 32)

    return decrypt(key, encrypted_file_key)


def x25519_decrypt_file_key(
    private_key: AgePrivateKey, derived_secret: ECPoint, encrypted_file_key: bytes
) -> bytes:
    """Decrypt ``file_key`` using the ``private_key`` and the two parameters returned by :func:`x25519_encrypt_file_key`.

    The inversion of :func:`x25519_encrypt_file_key` is: ::

        file key = decrypt[hkdf[salt, label](x25519(private key, derived_secret), 32)](encrypted file key)

    where ``salt`` is ``derived_secret`` || ``public key``, ``label`` is ``b"age-encryption.org/v1/X25519"``
    and ``derived_secret`` is the first parameter returned by :func:`x25519_encrypt_file_key`.
    """

    salt = derived_secret + private_key.public_key().public_bytes()

    return _x25519_decrypt_file_key2(
        private_key=private_key,
        derived_secret=derived_secret,
        encrypted_file_key=encrypted_file_key,
        salt=salt,
    )
