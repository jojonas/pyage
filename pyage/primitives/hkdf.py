
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def hkdf(salt, label, key, len):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=len,
        salt=salt,
        info=label,
        backend=default_backend()
    ).derive(key)
