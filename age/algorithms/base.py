import abc


class EncryptionBase:
    NAME = "<not implemented>"

    @abc.abstractmethod
    def encrypt(self, file_secret):
        raise NotImplementedError()

    def generate_recipient(self, file_key):
        parts = self.encrypt(file_key)
        return " ".join([
            "->",
            self.NAME,
            *parts
        ])


class DecryptionBase:
    NAME = "<not implemented>"

    @abc.abstractmethod
    def decrypt(self, *arguments):
        raise NotImplementedError()

    def parse_recipient(self, lines):
        assert lines.startswith("-> ")
        line = lines.replace("\n", "")
        parts = line.split()
        assert parts[0] == "->"
        assert parts[1] == self.NAME
        return self.decrypt(*parts[2:])
