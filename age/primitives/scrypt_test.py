from .scrypt import scrypt


# vectors 1 & 2 are not applicable because of different r, p settings

def test_scrypt_vector3():
    """Test case 3 from RFC 7914"""
    password = b"pleaseletmein"
    salt = b"SodiumChloride"
    N = 16384

    assert scrypt(salt, N)(password) == bytes.fromhex(
        "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887")

# vector 4 is (probably) too many rounds
