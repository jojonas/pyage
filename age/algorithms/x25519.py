from base import EncryptionBase, DecryptionBase

from age.primitives import encode, decode, random, hkdf, encrypt, decrypt, \
    x25519, CURVE_25519_BASEPOINT


X25519_RECIPIENT_LABEL = "X25519"
AGE_X25519_HKDF_LABEL = b"age-tool.com X25519"


class X25519Encryption(EncryptionBase):
    NAME = X25519_RECIPIENT_LABEL

    def __init__(self, public_key):
        self.public_key = public_key

    def encrypt(self, file_secret):
        ephemeral_secret = random(32)
        public_key = self.public_key.public_bytes()

        salt = x25519(ephemeral_secret, CURVE_25519_BASEPOINT) + public_key

        derived_secret = x25519(ephemeral_secret, CURVE_25519_BASEPOINT)

        key = hkdf(salt, AGE_X25519_HKDF_LABEL)(
            x25519(ephemeral_secret, public_key), 32)
        encrypted = encrypt(key)(file_secret)

        return encode(derived_secret), encode(encrypted)


class X25519Decryption(DecryptionBase):
    NAME = X25519_RECIPIENT_LABEL

    def __init__(self, private_key):
        self.private_key = private_key

    def decrypt(self, derived_secret, encrypted):
        derived_secret = decode(derived_secret)
        encrypted = decode(encrypted)

        private_key = self.private_key.private_bytes()
        public_key = self.private_key.public_key().public_bytes()

        salt = derived_secret + public_key

        # pubkey = x25519(privkey, 9)
        # x25519(a, x25519(b, 9)) = x25519(b, x25519(a, 9))

        # => x25519(ephemeral_secret, public_key)
        #  = x25519(ephemeral_secret, x25519(secret_key, 9))
        #  = x25519(secret_key, x25519(ephemeral_secret, 9))

        key = hkdf(salt, AGE_X25519_HKDF_LABEL)(
            x25519(private_key, derived_secret), 32)

        return decrypt(key)(encrypted)
