import os

from pytest import raises

from .encode import decode, encode


def test_encode_types():
    data = encode(b"Hello World!")
    assert isinstance(data, str)

    with raises(TypeError):
        encode("Hello String :(")


def test_decode_types():
    data = decode("SGVsbG8gV29ybGQh")
    assert isinstance(data, bytes)

    with raises(TypeError):
        decode(b"Hello Bytes :(")


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
