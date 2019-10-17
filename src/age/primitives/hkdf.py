from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__all__ = ["hkdf"]


def hkdf(salt: bytes, label: bytes, key: bytes, len: int) -> bytes:
    """Derive a key of len `len` using HKDF (:rfc:`5869`) using HMAC SHA-256

    :param salt: Salt
    :param label: Label
    :param key: Key
    :param len: Length of key to generate
    :returns: Key of length `len`

    >>> key = hkdf(b'', b'label', b'secret', 16)
    >>> len(key)
    16
    >>> key.hex()
    '112fefb269ce7dcb2ea6c7e952c104c1'
    """
    return HKDF(
        algorithm=hashes.SHA256(), length=len, salt=salt, info=label, backend=default_backend()
    ).derive(key)
