import typing

from age.algorithms.x25519 import _x25519_decrypt_file_key2, x25519_encrypt_file_key
from age.keys.agekey import AgePublicKey
from age.keys.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from age.primitives.hashes import sha256
from age.primitives.hkdf import hkdf
from age.primitives.x25519 import ECPoint, ECScalar, x25519_reduce, x25519_scalarmult

AGE_ED25519_LABEL = b"age-encryption.org/v1/ssh-ed25519"


def _tweak(ssh_key: bytes) -> ECScalar:
    return x25519_reduce(ECScalar(hkdf(salt=ssh_key, label=AGE_ED25519_LABEL, key=b"", len=64)))


def ssh_ed25519_encrypt_file_key(
    ed25519_public_key: Ed25519PublicKey, file_key: bytes
) -> typing.Tuple[bytes, ECPoint, bytes]:

    ssh_key = ed25519_public_key.binary_encoding()
    public_key_fingerprint = sha256(ssh_key)[:4]

    age_public_key = ed25519_public_key.to_age_public_key()

    pk_conv: ECPoint = age_public_key.public_bytes()
    pk_conv_tweak: ECPoint = x25519_scalarmult(_tweak(ssh_key), pk_conv)

    public_key = AgePublicKey.from_public_bytes(pk_conv_tweak)

    derived_secret, encrypted_file_key = x25519_encrypt_file_key(public_key, file_key)
    return public_key_fingerprint, derived_secret, encrypted_file_key


def ssh_ed25519_decrypt_file_key(
    ed25519_private_key: Ed25519PrivateKey,
    fingerprint: bytes,
    derived_secret: ECPoint,
    encrypted_file_key: bytes,
):
    ssh_key = ed25519_private_key.public_key().binary_encoding()
    expected_fingerprint = sha256(ssh_key)[:4]

    if fingerprint != expected_fingerprint:
        raise ValueError("Wrong SSH-ED25519 public key")

    tweak = _tweak(ssh_key)

    age_private_key = ed25519_private_key.to_age_private_key()

    pk_conv: ECPoint = age_private_key.public_key().public_bytes()
    pk_conv_tweak: ECPoint = x25519_scalarmult(tweak, pk_conv)

    derived_secret_tweak = x25519_scalarmult(tweak, derived_secret)

    salt = derived_secret + pk_conv_tweak

    return _x25519_decrypt_file_key2(
        private_key=age_private_key,
        derived_secret=derived_secret_tweak,
        encrypted_file_key=encrypted_file_key,
        salt=salt,
    )
