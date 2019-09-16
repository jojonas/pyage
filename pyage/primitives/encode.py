import base64
import textwrap


def encode(data):
    """Encode data to base64url (RFC 4648) text

    Accepts bytes and returns a string"""

    if not isinstance(data, bytes):
        raise ValueError("Can only encode() bytes.")

    encoded = base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    wrapped = "\n".join(textwrap.wrap(encoded, width=57))
    return wrapped


def decode(data):
    """Decode base64url (RFC 4648) encoded text

    Accepts a string and returns bytes"""

    if not isinstance(data, str):
        raise ValueError("Can only decode() strings.")
    return base64.urlsafe_b64decode(data + "===")
