import base64

__all__ = ["encode", "decode"]


def encode(data: bytes) -> str:
    """Encode data to base64url (RFC 4648) text

    :param data: Raw data
    :returns: Base64-encoded data
    :raises TypeError: if `data` is not a bytes instance

    >>> encode(b'test')
    'dGVzdA'
    """

    if not isinstance(data, bytes):
        raise TypeError("Can only encode() bytes.")

    return base64.b64encode(data).decode("ascii").rstrip("=")


def decode(data: str) -> bytes:
    """Decode base64url (RFC 4648) encoded text

    :param data: Base64-encoded data
    :returns: Raw data
    :raises TypeError: if ``data`` is not a string
    :raises ValueError: if base64-decoding fails (e.g. if `data` contains non-base64 characters)

    >>> decode('dGVzdA')
    b'test'
    """

    if not isinstance(data, str):
        raise TypeError("Can only decode() strings.")
    return base64.b64decode(data + "===")
