from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC


def hmac(key, message):
    mac = HMAC(
        key=key,
        algorithm=hashes.SHA256(),
        backend=default_backend())
    mac.update(message)
    return mac.finalize()
