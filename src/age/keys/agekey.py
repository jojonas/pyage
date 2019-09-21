from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from age.keys.base import DecryptionKey, EncryptionKey
from age.primitives.encode import decode, encode
from age.primitives.x25519 import ECPoint, ECScalar


class AgePrivateKey(DecryptionKey):
    PRIVATE_KEY_PREFIX = "AGE_SECRET_KEY_"

    def __init__(self, key: X25519PrivateKey):
        """Do not call directly"""
        assert isinstance(key, X25519PrivateKey)
        self._key: X25519PrivateKey = key

    def __repr__(self) -> str:
        clsname = self.__class__.__name__
        return f"<{clsname} {self.public_key().public_string()}>"

    @classmethod
    def generate(cls):
        """Generate a new age key"""
        return cls(X25519PrivateKey.generate())

    @classmethod
    def from_private_string(cls, data: str):
        """Read an age key from a private key string"""
        if not data.startswith(cls.PRIVATE_KEY_PREFIX):
            raise ValueError(f"Private keys must start with '{cls.PRIVATE_KEY_PREFIX}'.")

        key = data[len(cls.PRIVATE_KEY_PREFIX) :]
        bytes_ = decode(key)

        return cls.from_private_bytes(ECScalar(bytes_))

    @classmethod
    def from_private_bytes(cls, data: ECScalar):
        return cls(X25519PrivateKey.from_private_bytes(data))

    def private_string(self) -> str:
        """Generate a private (secret) key string for this key"""
        return self.PRIVATE_KEY_PREFIX + encode(self.private_bytes())

    def private_bytes(self) -> ECScalar:
        return self._key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def public_key(self):
        return AgePublicKey(self._key.public_key())


class AgePublicKey(EncryptionKey):
    PUBLIC_KEY_PREFIX = "pubkey:"

    def __init__(self, key: X25519PublicKey):
        """Do not call directly"""
        assert isinstance(key, X25519PublicKey)
        self._key: X25519PublicKey = key

    def __repr__(self):
        clsname = self.__class__.__name__
        return f"<{clsname} {self.public_string()}>"

    @classmethod
    def from_public_string(cls, data: str):
        """Read an age public key from a public key string"""
        if not data.startswith(cls.PUBLIC_KEY_PREFIX):
            raise ValueError(f"Public keys must start with '{cls.PUBLIC_KEY_PREFIX}'.")

        key = data[len(cls.PUBLIC_KEY_PREFIX) :]
        bytes_ = decode(key)

        return cls.from_public_bytes(ECPoint(bytes_))

    @classmethod
    def from_public_bytes(cls, data: ECPoint):
        return cls(X25519PublicKey.from_public_bytes(data))

    def public_string(self) -> str:
        """Generate a public key string for this key"""
        return self.PUBLIC_KEY_PREFIX + encode(self.public_bytes())

    def public_bytes(self) -> ECPoint:
        return self._key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
