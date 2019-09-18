from .hkdf import hkdf


def test_hkdf():
    """Test Case 1, RFC 5869, section A.1"""

    keying_material = bytes.fromhex(
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    assert len(keying_material) == 22

    salt = bytes.fromhex("000102030405060708090a0b0c")
    assert len(salt) == 13

    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    assert len(info) == 10

    L = 42

    key = hkdf(salt, info)(keying_material, L)
    assert len(key) == L

    assert key == bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
        "34007208d5b887185865")


def test_hkdf_long():
    """Test Case 2, RFC 5869, section A.2"""

    keying_material = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
        "404142434445464748494a4b4c4d4e4f")
    assert len(keying_material) == 80

    salt = bytes.fromhex(
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
    assert len(salt) == 80

    info = bytes.fromhex(
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    assert len(info) == 80

    L = 82

    key = hkdf(salt, info)(keying_material, L)
    assert len(key) == L

    assert key == bytes.fromhex(
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" +
        "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71" +
        "cc30c58179ec3e87c14c01d5c1f3434f1d87")


def test_hkdf_zerosalt():
    """Test Case 3, RFC 5869, section A.3"""

    keying_material = bytes.fromhex(
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    assert len(keying_material) == 22

    salt = b""
    info = b""

    L = 42

    key = hkdf(salt, info)(keying_material, L)
    assert len(key) == L

    assert key == bytes.fromhex(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d" +
        "9d201395faa4b61a96c8")
