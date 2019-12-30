from .agekey import AgePrivateKey, AgePublicKey

SPEC_TEST_BYTES = b"\x42" * 32
SPEC_TEST_PUBLIC_KEY = "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj"
SPEC_TEST_PRIVATE_KEY = "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX"


def test_key_encoding():
    private_key = AgePrivateKey.from_private_bytes(SPEC_TEST_BYTES)
    assert private_key.private_string().lower() == SPEC_TEST_PRIVATE_KEY.lower()
    public_key = private_key.public_key()
    assert public_key.public_string().lower() == SPEC_TEST_PUBLIC_KEY.lower()


def test_key_decoding():
    private_key = AgePrivateKey.from_private_string(SPEC_TEST_PRIVATE_KEY)
    assert private_key.private_bytes() == SPEC_TEST_BYTES
    public_key = AgePublicKey.from_public_string(SPEC_TEST_PUBLIC_KEY)
    assert private_key.public_key() == public_key
