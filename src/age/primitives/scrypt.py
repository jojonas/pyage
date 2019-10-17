from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

__all__ = ["scrypt"]


def scrypt(salt: bytes, N: int, password: bytes) -> bytes:
    """Derive a key from `password` and `salt`

    For the choise of `N`, see `<https://blog.filippo.io/the-scrypt-parameters/>`_.

    :param salt: Salt
    :param N: Scrypt cost
    :param password: Password
    """
    kdf = Scrypt(salt=salt, length=32, n=N, r=8, p=1, backend=default_backend())
    return kdf.derive(password)
