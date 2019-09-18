import typing

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_ssh_public_key, \
    load_pem_private_key
from cryptography.hazmat.backends import default_backend

__all__ = ['rsa_encrypt', 'rsa_decrypt']


def _padding(label: bytes) -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=label,
    )


def rsa_encrypt(ssh_key: bytes, label: bytes) \
        -> typing.Callable[[bytes], bytes]:

    public_key = load_ssh_public_key(
        data=ssh_key,
        backend=default_backend()
    )

    def func(plaintext: bytes) -> bytes:
        return public_key.encrypt(
            plaintext=plaintext,
            padding=_padding(label)
        )
    return func


def rsa_decrypt(pem_data: bytes, label: bytes) \
        -> typing.Callable[[bytes], bytes]:

    # TODO: Add support for password-protected private keys

    private_key = load_pem_private_key(
        pem_data,
        password=None,
        backend=default_backend()
    )

    def func(ciphertext: bytes) -> bytes:
        return private_key.decrypt(
            ciphertext=ciphertext,
            padding=_padding(label)
        )
    return func
