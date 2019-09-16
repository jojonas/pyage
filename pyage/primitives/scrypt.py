import hashlib


def scrypt(salt, N, password):
    return hashlib.scrypt(
        password=password,
        salt=salt,
        n=N,
        r=8,
        p=1)
