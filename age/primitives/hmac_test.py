from .hmac import hmac


def test_hmac_vector_1():
    """Test case 1 from RFC 4231"""

    key = b"\x0B"*20
    data = b"Hi There"
    assert hmac(key)(data) == bytes.fromhex(
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")


def test_hmac_vector_2():
    """Test case 2 from RFC 4231"""

    key = b"Jefe"
    data = b"what do ya want for nothing?"
    assert hmac(key)(data) == bytes.fromhex(
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")


def test_hmac_vector3():
    """Test case 3 from RFC 4231"""

    key = b"\xAA"*20
    data = b"\xDD"*50
    assert hmac(key)(data) == bytes.fromhex(
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")


def test_hmac_vector4():
    """Test case 4 from RFC 4231"""

    key = bytes.fromhex("0102030405060708090a0b0c0d0e0f10111213141516171819")
    data = b"\xCD"*50
    assert hmac(key)(data) == bytes.fromhex(
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b")


def test_hmac_vector5():
    """Test case 5 from RFC 4231"""

    key = b"\x0C"*20
    data = b"Test With Truncation"
    assert hmac(key)(data)[:16] == bytes.fromhex(
        "a3b6167473100ee06e0c796c2955552b")


def test_hmac_vector6():
    """Test case 6 from RFC 4231"""

    key = b"\xAA"*131
    data = b"Test Using Larger Than Block-Size Key - Hash Key First"
    assert hmac(key)(data) == bytes.fromhex(
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")


def test_hmac_vector7():
    """Test case 7 from RFC 4231"""

    key = b"\xAA"*131
    data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
    assert hmac(key)(data) == bytes.fromhex(
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2")
