import abc


from age.primitives import encode, decode, random, hkdf, encrypt, decrypt, hmac, x25519, CURVE_25519_BASEPOINT, scrypt, rsa_encrypt, sha256


def header_aead(header, file_key):
    key = hkdf("", "header")(file_key, 32)
    mac = hmac(key)(header)
    return f"--- ChaChaPoly {encode(mac)}"


def encrypt_body(file_key, data):
    nonce = random(16)
    key = hkdf(nonce, b"payload")(file_key, 32)


def scrypt_recipient(password, file_key):
    salt = random(19)
    cost = 32768  # whats an appropriate cost?

    key = scrypt(salt, cost)(password)
    encrypted = encrypt(key)(file_key)

    return f"-> scrypt {encode(salt)} {cost} {encode(encrypted)}"


def ssh_rsa_recipient(ssh_key, file_key):
    fingerprint = sha256(ssh_key)[:4]
    label = "age-tool.com ssh-rsa"
    encrypted = rsa_encrypt(ssh_key, label)(file_key)
    return f"-> ssh-rsa {encode(fingerprint)} {encode(encrypted)}"


def foo():
    # x = AgePrivateKey("AGE_SECRET_KEY_RQvvHYA29yZk8Lelpiz8lW7QdlxkE4djb1NOjLgeUFg")
    # recipient_line = x.encrypt(file_secret)

    key = AgePublicKey("pubkey:98W5ph53zfPGOzEOH-fMojQ4jUY7VLEmtmozREqnw4I")
    recipient_line = x25519_encrypt(key, file_secret)

    key2 = AgePrivateKey(
        "AGE_SECRET_KEY_RQvvHYA29yZk8Lelpiz8lW7QdlxkE4djb1NOjLgeUFg")
    file_secret = x25519_decrypt(key2, recipient_line)
