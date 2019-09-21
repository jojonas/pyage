from .base import DecryptionKey, EncryptionKey


class PasswordKey(EncryptionKey, DecryptionKey):
    def __init__(self, value: bytes):
        self.value = value

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return f"<{self.__class__.__name__}>"
