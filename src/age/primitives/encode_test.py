import os

from pytest import raises

from .encode import decode, encode


def test_encode_types():
    data = encode(b"Hello World!")
    assert isinstance(data, str)

    with raises(TypeError):
        # Ignoring typing errors, because that's the point!
        encode("Hello String :(")  # type: ignore


def test_decode_types():
    data = decode("SGVsbG8gV29ybGQh")
    assert isinstance(data, bytes)

    with raises(TypeError):
        # Ignoring typing errors, because that's the point!
        decode(b"Hello Bytes :(")  # type: ignore


def test_encode():
    encoded = encode(b"Hello World!")
    assert encoded == "SGVsbG8gV29ybGQh"


def test_encode_decode():
    data = os.urandom(256)
    encoded = encode(data)
    decoded = decode(encoded)
    assert decoded == data


def test_decode_garbage():
    assert decode("SGVsbG8gV29ybGQ!") == decode("SGVsbG8gV29ybGQ")
