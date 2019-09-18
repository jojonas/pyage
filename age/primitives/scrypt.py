import hashlib
import typing

__all__ = ['scrypt']


def scrypt(salt: bytes, N: int) -> typing.Callable[[bytes], bytes]:
    def func(password: bytes) -> bytes:
        return hashlib.scrypt(
            password=password,
            salt=salt,
            n=N,
            r=8,
            p=1,
            maxmem=1024*1024*1024,
            dklen=32)
    return func
