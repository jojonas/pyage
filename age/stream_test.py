import os

from pytest import raises

from .stream import stream_encrypt, stream_decrypt, _pack_nonce, _chunk


def test_chunk():
    data = b"123456789"

    expected_chunks_2 = [b"12", b"34", b"56", b"78", b"9"]
    for i, chunk_ in enumerate(_chunk(data, 2)):
        assert chunk_ == expected_chunks_2[i]

    expected_chunks_3 = [b"123", b"456", b"789"]
    for i, chunk_ in enumerate(_chunk(data, 3)):
        assert chunk_ == expected_chunks_3[i]

    expected_chunks_4 = [b"1234", b"5678", b"9"]
    for i, chunk_ in enumerate(_chunk(data, 4)):
        assert chunk_ == expected_chunks_4[i]

    expected_chunks_20 = [data]
    for i, chunk_ in enumerate(_chunk(data, 20)):
        assert chunk_ == expected_chunks_20[i]


def test_pack_nonce():
    assert _pack_nonce(0x03, False) == bytes.fromhex(
        "00 00 00 00 00 00 00 00 00 00 03 00"
    )
    assert _pack_nonce(0x5544332211, False) == bytes.fromhex(
        "00 00 00 00 00 00 55 44 33 22 11 00"
    )
    assert _pack_nonce(0x5544332211, True) == bytes.fromhex(
        "00 00 00 00 00 00 55 44 33 22 11 01"
    )
    assert _pack_nonce(0x5544332211AABBCCDDEEFF, False) == bytes.fromhex(
        "55 44 33 22 11 aa bb cc dd ee ff 00"
    )
    assert _pack_nonce(0x5544332211AABBCCDDEEFF, True) == bytes.fromhex(
        "55 44 33 22 11 aa bb cc dd ee ff 01"
    )

    with raises(AssertionError):
        _pack_nonce(0x665544332211AABBCCDDEEFF, True)


def test_stream():
    key = os.urandom(32)
    data = os.urandom(100 * 1024)

    ciphertext = stream_encrypt(key, data)
    assert ciphertext != data

    plaintext = stream_decrypt(key, ciphertext)
    assert len(data) == len(plaintext)
    assert data == plaintext
