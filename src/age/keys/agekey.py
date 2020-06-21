from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from age.keys.base import DecryptionKey, EncryptionKey
from age.primitives.bech32 import bech32_decode, bech32_encode
from age.primitives.x25519 import ECPoint, ECScalar


class AgePrivateKey(DecryptionKey):
    # HRP = human-readable part
    PRIVATE_KEY_BECH32_HRP = "age-secret-key-"

    def __init__(self, key: X25519PrivateKey):
        """Do not call directly"""
        assert isinstance(key, X25519PrivateKey)
        self._key: X25519PrivateKey = key

    def __repr__(self) -> str:
        clsname = self.__class__.__name__
        return f"<{clsname} {self.public_key().public_string()}>"

    def __eq__(self, other):
        return isinstance(other, self.__class__) and (other.private_bytes() == self.private_bytes())

    def __hash__(self):
        return hash(self.private_bytes())

    @classmethod
    def generate(cls):
        """Generate a new age key"""
        return cls(X25519PrivateKey.generate())

    @classmethod
    def from_private_string(cls, data: str):
        """Read an age key from a private key string"""
        data = data.lower()

        hrp, bytes_ = bech32_decode(data)
        if hrp != cls.PRIVATE_KEY_BECH32_HRP or len(bytes_) != 32:
            raise ValueError("invalid age private key")

        return cls.from_private_bytes(ECScalar(bytes_))

    @classmethod
    def from_private_bytes(cls, data: ECScalar):
        return cls(X25519PrivateKey.from_private_bytes(data))

    def private_string(self) -> str:
        """Generate a private (secret) key string for this key"""
        return bech32_encode(self.PRIVATE_KEY_BECH32_HRP, self.private_bytes()).upper()

    def private_bytes(self) -> ECScalar:
        return ECScalar(
            self._key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    def public_key(self):
        return AgePublicKey(self._key.public_key())


class AgePublicKey(EncryptionKey):
    # HRP = human-readable part
    PUBLIC_KEY_BECH32_HRP = "age"

    def __init__(self, key: X25519PublicKey):
        """Do not call directly"""
        assert isinstance(key, X25519PublicKey)
        self._key: X25519PublicKey = key

    def __repr__(self):
        clsname = self.__class__.__name__
        return f"<{clsname} {self.public_string()}>"

    def __eq__(self, other):
        return isinstance(other, self.__class__) and (other.public_bytes() == self.public_bytes())

    def __hash__(self):
        return hash(self.public_bytes())

    @classmethod
    def from_public_string(cls, data: str):
        """Read an age public key from a public key string"""
        data = data.lower()

        hrp, key = bech32_decode(data)
        if hrp != cls.PUBLIC_KEY_BECH32_HRP:
            raise ValueError("invalid age public key")

        return cls.from_public_bytes(ECPoint(key))

    @classmethod
    def from_public_bytes(cls, data: ECPoint):
        return cls(X25519PublicKey.from_public_bytes(data))

    def public_string(self) -> str:
        """Generate a public key string for this key"""
        return bech32_encode(self.PUBLIC_KEY_BECH32_HRP, self.public_bytes())

    def public_bytes(self) -> ECPoint:
        return ECPoint(
            self._key.public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            )
        )
