from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC as CryptoHMAC

__all__ = ["HMAC"]


def _reduce_key(key: bytes) -> bytes:
    if len(key) > 32:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(key)
        key = digest.finalize()
    return key


class HMAC:
    """HMAC-SHA256 from :rfc:`2104`

    :param key: Shared symmetrical key, used for authentication, needed for authentication checks
    """

    def __init__(self, key: bytes):
        key = _reduce_key(key)
        self.mac: CryptoHMAC = CryptoHMAC(
            key=key, algorithm=hashes.SHA256(), backend=default_backend()
        )

    def generate(self, message: bytes) -> bytes:
        """Generate authentication value for the given message"""
        self.mac.update(message)
        return self.mac.finalize()

    def verify(self, message: bytes, tag: bytes) -> None:
        """Verify authenticaion value for the given message

        Raises :class:`cryptography.exceptions.InvalidSignature` on failed validation."""
        self.mac.update(message)
        self.mac.verify(tag)

    def is_valid(self, message: bytes, tag: bytes) -> bool:
        """Check whether authentication value for the given message is correct

        :returns: `True` if validation succeeds, `False` otherwise"""
        try:
            self.verify(message, tag)
        except InvalidSignature:
            return False
        else:
            return True
