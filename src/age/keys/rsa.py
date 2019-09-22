import base64
import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey as RSAPrivateKey_
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey as RSAPublicKey_
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
    load_ssh_public_key,
)

from age.openssh_keys import load_openssh_private_key

from .base import DecryptionKey, EncryptionKey

__all__ = ["RSAPrivateKey", "RSAPublicKey"]

RSA_DEFAULT_PUBLIC_EXPONENT: int = 65537
OPENSSH_DEFAULT_KEY_COMMENT = "age"


class RSAPrivateKey(DecryptionKey):
    def __init__(self, key: RSAPrivateKey_):
        """Do not call directly"""
        assert isinstance(key, RSAPrivateKey_)
        self._key: RSAPrivateKey_ = key

    def __repr__(self) -> str:
        clsname = self.__class__.__name__
        return f"<{clsname} {self.public_key().fingerprint()}>"

    @classmethod
    def generate(cls, key_size: int = 4096):
        generated_key = generate_private_key(
            RSA_DEFAULT_PUBLIC_EXPONENT, key_size, backend=default_backend()
        )
        return cls(generated_key)

    @classmethod
    def from_pem(cls, pem_data: bytes, password: bytes = None):
        try:
            private_key = load_pem_private_key(
                pem_data, password=password, backend=default_backend()
            )
        except ValueError:
            # OpenSSH private keys are special snowflakes
            private_key = load_openssh_private_key(pem_data, passphrase=password)
        assert isinstance(private_key, RSAPrivateKey_)
        return cls(private_key)

    def public_key(self):
        return RSAPublicKey(self._key.public_key())


class RSAPublicKey(EncryptionKey):
    def __init__(self, key: RSAPublicKey_):
        """Do not call directly"""
        assert isinstance(key, RSAPublicKey_)
        self._key: RSAPublicKey_ = key

    def __repr__(self) -> str:
        clsname = self.__class__.__name__
        return f"<{clsname} {self.fingerprint()}>"

    def __eq__(self, other):
        return isinstance(other, self.__class__) and (
            other.binary_encoding() == self.binary_encoding()
        )

    def __hash__(self):
        return hash(self.binary_encoding())

    @classmethod
    def from_ssh_public_key(cls, ssh_public_key_data: bytes):
        """Load RSA public key encoded according to :rfc:`4253`"""
        public_key = load_ssh_public_key(data=ssh_public_key_data, backend=default_backend())
        assert isinstance(public_key, RSAPublicKey_)
        return cls(public_key)

    def binary_encoding(self) -> bytes:
        serialized = self._key.public_bytes(encoding=Encoding.OpenSSH, format=PublicFormat.OpenSSH)
        type_, base64encoded_data, *_ = serialized.split()
        assert type_ == b"ssh-rsa"
        return base64.b64decode(base64encoded_data + b"===")

    def fingerprint_line(
        self, algorithm: str = "MD5", comment: str = OPENSSH_DEFAULT_KEY_COMMENT
    ) -> str:
        return " ".join(
            [str(self._key.key_size), self.fingerprint(algorithm=algorithm), comment, "(RSA)"]
        )

    def fingerprint(self, algorithm: str = "MD5") -> str:
        raw = self.binary_encoding()

        if algorithm == "MD5":
            digest = hashlib.md5(raw).digest()
            return "MD5:" + ":".join(f"{b:02x}" for b in digest).lower()
        elif algorithm == "SHA256":
            digest = hashlib.sha256(raw).digest()
            return "SHA256:" + base64.b64encode(digest).rstrip(b"=").decode("ascii")
        else:
            raise ValueError("Unknown fingerprinting algorithm")
