from .ed25519 import Ed25519PublicKey, Ed25519PrivateKey

PUBLIC_KEY = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDgEg0dirYJ1xRV3EkPFXQE7hYMs3cumY8qBzEE/1Xk4 test key"


def test_fingerprint():
    key = Ed25519PublicKey.from_ssh_public_key(PUBLIC_KEY)
    assert (
        key.fingerprint("MD5")
        == "MD5:d3:9f:fc:84:80:ed:99:73:1c:1b:e4:77:ef:15:53:1a"
    )
    assert (
        key.fingerprint_line("MD5")
        == "256 MD5:d3:9f:fc:84:80:ed:99:73:1c:1b:e4:77:ef:15:53:1a age (ED25519)"
    )
    assert (
        key.fingerprint("SHA256")
        == "SHA256:d1NMPpXeiZSB8mrreniR7FmPcu2Hoa9eWAxmJx6zVno"
    )
    assert (
        key.fingerprint_line("SHA256")
        == "256 SHA256:d1NMPpXeiZSB8mrreniR7FmPcu2Hoa9eWAxmJx6zVno age (ED25519)"
    )


def test_ed25519_to_curve25519():
    key = Ed25519PrivateKey.generate()

    pub1 = key.to_age_private_key().public_key()
    pub2 = key.public_key().to_age_public_key()

    assert pub1.public_bytes() == pub2.public_bytes()
