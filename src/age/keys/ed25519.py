import base64
import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey as Ed25519PrivateKey_,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey as Ed25519PublicKey_
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_ssh_public_key,
)
from nacl.bindings import crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519

from age.keys.agekey import AgePrivateKey, AgePublicKey
from age.openssh_keys import load_openssh_private_key

from .base import DecryptionKey, EncryptionKey

__all__ = ["Ed25519PrivateKey", "Ed25519PublicKey"]

OPENSSH_DEFAULT_KEY_COMMENT = "age"
ED25519_KEY_SIZE = 256


class Ed25519PrivateKey(DecryptionKey):
    def __init__(self, key: Ed25519PrivateKey_):
        """Do not call directly"""
        assert isinstance(key, Ed25519PrivateKey_)
        self._key: Ed25519PrivateKey_ = key

    def __repr__(self) -> str:
        clsname = self.__class__.__name__
        return f"<{clsname} {self.public_key().fingerprint()}>"

    @classmethod
    def generate(cls):
        return cls(Ed25519PrivateKey_.generate())

    @classmethod
    def from_pem(cls, pem_data: bytes, password: bytes = None):
        try:
            private_key = load_pem_private_key(
                pem_data, password=password, backend=default_backend()
            )
        except ValueError:
            # OpenSSH private keys are special snowflakes
            private_key = load_openssh_private_key(pem_data, passphrase=password)
        assert isinstance(private_key, Ed25519PrivateKey_)
        return cls(private_key)

    def public_key(self):
        return Ed25519PublicKey(self._key.public_key())

    def to_age_private_key(self) -> AgePrivateKey:
        # use pynacl for this conversion
        ed25519_pk = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ed25519_sk = self._key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        curve25519_sk = crypto_sign_ed25519_sk_to_curve25519(ed25519_sk + ed25519_pk)
        private_key = X25519PrivateKey.from_private_bytes(curve25519_sk)
        return AgePrivateKey(private_key)


class Ed25519PublicKey(EncryptionKey):
    def __init__(self, key: Ed25519PublicKey_):
        """Do not call directly"""
        assert isinstance(key, Ed25519PublicKey_)
        self._key: Ed25519PublicKey_ = key

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
        assert isinstance(public_key, Ed25519PublicKey_)
        return cls(public_key)

    def binary_encoding(self) -> bytes:
        serialized = self._key.public_bytes(encoding=Encoding.OpenSSH, format=PublicFormat.OpenSSH)
        type_, base64encoded_data, *_ = serialized.split()
        assert type_ == b"ssh-ed25519"
        return base64.b64decode(base64encoded_data + b"===")

    def fingerprint_line(
        self, algorithm: str = "MD5", comment: str = OPENSSH_DEFAULT_KEY_COMMENT
    ) -> str:
        return " ".join(
            [str(ED25519_KEY_SIZE), self.fingerprint(algorithm=algorithm), comment, "(ED25519)"]
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

    def to_age_public_key(self) -> AgePublicKey:
        # use pynacl for this conversion
        ed25519_pk = self._key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        curve25519_pk = crypto_sign_ed25519_pk_to_curve25519(ed25519_pk)
        public_key = X25519PublicKey.from_public_bytes(curve25519_pk)
        return AgePublicKey(public_key)
