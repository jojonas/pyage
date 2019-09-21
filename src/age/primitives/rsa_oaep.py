from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from age.keys.rsa import RSAPrivateKey, RSAPublicKey

__all__ = ["rsa_encrypt", "rsa_decrypt"]


def _padding(label: bytes) -> padding.OAEP:
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label)


def rsa_encrypt(public_key: RSAPublicKey, label: bytes, plaintext: bytes) -> bytes:
    """Encrypt `plaintext` using RSA with OAEP padding (:rfc:`8017`)"""
    return public_key._key.encrypt(plaintext=plaintext, padding=_padding(label))


def rsa_decrypt(private_key: RSAPrivateKey, label: bytes, ciphertext: bytes) -> bytes:
    """Deccrypt `ciphertext` using RSA with OAEP padding (:rfc:`8017`)"""

    return private_key._key.decrypt(ciphertext=ciphertext, padding=_padding(label))
