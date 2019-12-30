import base64
import io
import re
import typing

START_RE = re.compile(r"^-----BEGIN ([^-]*)-----\n$")
END_RE = re.compile(r"^-----END ([^-]*)-----\n?$")

PEM_LINE_LENGTH = 64
AGE_PEM_LABEL = "AGE ENCRYPTED FILE"


def _is_valid_label(label: str) -> bool:
    if label.upper() != label:
        return False

    if "-" in label:
        return False

    if label.startswith(" ") or label.endswith(" "):
        return False

    return True


def read_ascii_armored(
    file: typing.TextIO, strict_line_length: bool = True
) -> typing.Iterator[typing.Tuple[str, bytes]]:
    in_label: typing.Optional[str] = None
    buffer: typing.List[str] = []

    for line in file:
        if in_label is None:
            start_match = START_RE.match(line)
            if start_match:
                label = start_match.group(1)
                if _is_valid_label(label):
                    in_label = label
                else:
                    raise ValueError(f"invalid label: {label}")
            else:
                # ignore everything before the START marker
                continue
        else:
            end_match = END_RE.match(line)
            if end_match:
                label = end_match.group(1)
                if label == in_label:
                    if strict_line_length:
                        for i, buffer_line in enumerate(buffer):
                            if len(buffer_line) > PEM_LINE_LENGTH:
                                raise ValueError(f"PEM line too long: {buffer_line}")
                            elif len(buffer_line) < PEM_LINE_LENGTH and i != len(buffer) - 1:
                                raise ValueError("PEM line too short")

                    data = base64.b64decode("".join(buffer), validate=True)
                    yield (in_label, data)

                    in_label = None
                    buffer.clear()
                else:
                    raise ValueError(f"unexpected boundary: {line!r}")
            else:
                buffer.append(line.strip())

    if in_label is not None:
        raise ValueError(f"did not close section for label {in_label!r}")


def write_ascii_armored(file: typing.TextIO, label: str, data: bytes) -> None:
    if not _is_valid_label(label):
        raise ValueError(f"inalid label: {label}")

    file.write(f"-----BEGIN {label}-----\n")
    encoded = base64.b64encode(data).decode("ascii")
    for i in range(0, len(encoded), 64):
        chunk = encoded[i : i + 64]
        file.write(chunk)
        file.write("\n")
    file.write(f"-----END {label}-----\n")


class AsciiArmoredOutput(io.RawIOBase):
    def __init__(self, label: str, stream: typing.BinaryIO):
        self._stream: typing.BinaryIO = stream
        self._text_stream: typing.TextIO = io.TextIOWrapper(stream, "utf-8")
        self._plaintext_buffer: bytes = b""
        self._label: str = label

    def writable(self):
        return True

    def write(self, data):
        self._plaintext_buffer += data
        return len(data)

    def close(self):
        if not self.closed:
            self._encode_buffer()
            super().close()

    def _encode_buffer(self):
        write_ascii_armored(self._text_stream, self._label, self._plaintext_buffer)
        self._plaintext_buffer = b""


class AsciiArmoredInput(io.RawIOBase):
    def __init__(self, label: str, stream: typing.BinaryIO):
        self._stream: typing.BinaryIO = stream
        self._text_stream: typing.TextIO = io.TextIOWrapper(stream, "utf-8")
        self._plaintext_stream: typing.Optional[typing.BinaryIO] = None
        self._label: str = label

        self._decode_body()

    def readable(self):
        return True

    def read(self, size=-1):
        assert self._plaintext_stream is not None
        return self._plaintext_stream.read(size)

    def _decode_body(self):
        count = 0

        data = None
        for label, decoded in read_ascii_armored(self._text_stream):
            if label == self._label:
                data = decoded
                count += 1

        if count == 0:
            raise ValueError(f"label {label} not found")
        if count > 1:
            raise ValueError(f"only one {label}-section allowed")

        self._plaintext_stream = io.BytesIO(data)
        self._plaintext_stream.seek(0)
