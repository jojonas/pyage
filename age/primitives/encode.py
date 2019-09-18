import base64
import textwrap

__all__ = ['encode', 'decode']


def encode(data: bytes) -> str:
    """Encode data to base64url (RFC 4648) text"""

    if not isinstance(data, bytes):
        raise ValueError("Can only encode() bytes.")

    encoded = base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    wrapped = textwrap.fill(encoded, width=57)
    return wrapped


def decode(data: str) -> bytes:
    """Decode base64url (RFC 4648) encoded text"""

    if not isinstance(data, str):
        raise ValueError("Can only decode() strings.")
    return base64.urlsafe_b64decode(data + "===")
