import typing

from age.keys.rsa import RSAPrivateKey, RSAPublicKey
from age.primitives.hashes import sha256
from age.primitives.rsa_oaep import rsa_decrypt, rsa_encrypt

AGE_RSA_PADDING_LABEL = b"age-encryption.org/v1/ssh-rsa"


def ssh_rsa_encrypt_file_key(
    public_key: RSAPublicKey, file_key: bytes
) -> typing.Tuple[bytes, bytes]:

    public_key_fingerprint = sha256(public_key.binary_encoding())[:4]
    encrypted_file_key = rsa_encrypt(
        public_key=public_key, label=AGE_RSA_PADDING_LABEL, plaintext=file_key
    )

    return public_key_fingerprint, encrypted_file_key


def ssh_rsa_decrypt_file_key(
    private_key: RSAPrivateKey, fingerprint: bytes, encrypted_file_key: bytes
) -> bytes:
    expected_fingerprint = sha256(private_key.public_key().binary_encoding())[:4]
    if fingerprint != expected_fingerprint:
        raise ValueError("Wrong SSH-RSA public key")

    return rsa_decrypt(
        private_key=private_key, label=AGE_RSA_PADDING_LABEL, ciphertext=encrypted_file_key
    )
