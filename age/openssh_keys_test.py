from pytest import raises

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .openssh_keys import load_openssh_private_key, WrongPassphrase


RSA_PRIVATE_KEY = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEA7qa64E2APb7+U5fSbrZGsAVrL4F2gge1YJoj2BaHUFei6fwXmHzE
SA+zrCNrPkBRUiMFDGBVrDc1DwAgoZF89Ik4jxd6TjfRZ77z24XD2GRiZfsJjSda/WgdPc
NnG4F0hEp+HcyIcaP7l61rQpWZQ7aVSpJxrIUWpz9qEAktOHsAAAIQ/qZ0yv6mdMoAAAAH
c3NoLXJzYQAAAIEA7qa64E2APb7+U5fSbrZGsAVrL4F2gge1YJoj2BaHUFei6fwXmHzESA
+zrCNrPkBRUiMFDGBVrDc1DwAgoZF89Ik4jxd6TjfRZ77z24XD2GRiZfsJjSda/WgdPcNn
G4F0hEp+HcyIcaP7l61rQpWZQ7aVSpJxrIUWpz9qEAktOHsAAAADAQABAAAAgQDZHZiwTf
HYuvUYSexpSq0+oH9mRcrx+19Y1oK7qatLPZ96bh1tXj0YLijQ95wuk0coibGjE9V9ivBb
iEsnknvxH1MXGqTp1m8akJBEm/szvtDg7FBA5xQOy4DgmcBIvFyJp8D3cR0ak6ktzkfEEN
VHnG+NdHGsxTRIVmJiA/0E4QAAAEAzu5hx9oftJ6cMjjfU50LzFV1uadBff2Vkba/ayXTL
VqHGOiqZhvGrF8BnSafTT4vcyu51/nE4Cs+Jh6iUA8m2AAAAQQD3vI4fZpr7bWKhwKyM4J
3MJAjXpqRxVsPiJl0BEUG05aMw1uXvllYzUpqiL0/DMsK7CbpW9haPE+Iej71ZB0zRAAAA
QQD2nJhSONIoQPZd5+gUKnusZBj1Z6t02QSu7EAw90XG9ChgtMA95NY8cjZhFmLf9ml6+/
EC2Vl35LMGAYA0ExOLAAAAF2pvbmFzQGpvbmFzLWxhcHRvcC1hcmNoAQID
-----END OPENSSH PRIVATE KEY-----"""
RSA_PUBLIC_KEY = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDuprrgTYA9vv5Tl9JutkawBWsvgXaCB7VgmiPYFodQV6Lp/BeYfMRID7OsI2s+QFFSIwUMYFWsNzUPACChkXz0iTiPF3pON9FnvvPbhcPYZGJl+wmNJ1r9aB09w2cbgXSESn4dzIhxo/uXrWtClZlDtpVKknGshRanP2oQCS04ew== test key"

DSA_PRIVATE_KEY = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABsQAAAAdzc2gtZH
NzAAAAgQCYOtn50sTXFkQYZSxim9gT+NwqzXf8FQXy0MgZKleLhM3vQAeL+tT63PWUVECY
90EhRsacpg2pn0pM4qpb9Iwgo1VNEU4bjNWvW53Hl7BcVfrx8lqyN/RAZUs1feQK3UC296
LSKk//gsYrsQYFGejcTLojCAgoowK3pD1UCwX7IwAAABUA1/G3VnBm7uBRWhPl+FCW9Cci
FIEAAACAHZ+0EFji4KsRrHU9oQl7TaaI5uhk+LSX1LEuwaXDZx1NDCxMy9CwJL1gF286rP
DgY3TMK0UrRf9lNq/J4jq+HM2yWzRhKec5F9KFjU34ZceGCIXAaxu6fgD24h//fs0ze4UI
+J623b1uR8KYS4T48dw4oq4iRbqWq/+lC5XBa20AAACAJyitggvASu2kNUXAuMKBZ585au
Ldku+uoe0mv8tZ7hlHvZcNcH/CH9YHOfs+Vff1/8qFjsRUyMaZdJhXi3Ou6w0dauOztC2j
TOYcHncDRIH3pee7VRRkn3OINR0HDWUQsCKqdDZijInrFeBfN0DC+rewn+MUhjb7Iqn5Vm
noyqAAAAHwFGH6exRh+nsAAAAHc3NoLWRzcwAAAIEAmDrZ+dLE1xZEGGUsYpvYE/jcKs13
/BUF8tDIGSpXi4TN70AHi/rU+tz1lFRAmPdBIUbGnKYNqZ9KTOKqW/SMIKNVTRFOG4zVr1
udx5ewXFX68fJasjf0QGVLNX3kCt1Atvei0ipP/4LGK7EGBRno3Ey6IwgIKKMCt6Q9VAsF
+yMAAAAVANfxt1ZwZu7gUVoT5fhQlvQnIhSBAAAAgB2ftBBY4uCrEax1PaEJe02miOboZP
i0l9SxLsGlw2cdTQwsTMvQsCS9YBdvOqzw4GN0zCtFK0X/ZTavyeI6vhzNsls0YSnnORfS
hY1N+GXHhgiFwGsbun4A9uIf/37NM3uFCPiett29bkfCmEuE+PHcOKKuIkW6lqv/pQuVwW
ttAAAAgCcorYILwErtpDVFwLjCgWefOWri3ZLvrqHtJr/LWe4ZR72XDXB/wh/WBzn7PlX3
9f/KhY7EVMjGmXSYV4tzrusNHWrjs7Qto0zmHB53A0SB96Xnu1UUZJ9ziDUdBw1lELAiqn
Q2YoyJ6xXgXzdAwvq3sJ/jFIY2+yKp+VZp6MqgAAAAFB37lXXdxSCFGo2KUGPk8XX1Leu1
AAAAF2pvbmFzQGpvbmFzLWxhcHRvcC1hcmNoAQIDBA==
-----END OPENSSH PRIVATE KEY-----"""
DSA_PUBLIC_KEY = b"ssh-dss AAAAB3NzaC1kc3MAAACBAJg62fnSxNcWRBhlLGKb2BP43CrNd/wVBfLQyBkqV4uEze9AB4v61Prc9ZRUQJj3QSFGxpymDamfSkziqlv0jCCjVU0RThuM1a9bnceXsFxV+vHyWrI39EBlSzV95ArdQLb3otIqT/+CxiuxBgUZ6NxMuiMICCijArekPVQLBfsjAAAAFQDX8bdWcGbu4FFaE+X4UJb0JyIUgQAAAIAdn7QQWOLgqxGsdT2hCXtNpojm6GT4tJfUsS7BpcNnHU0MLEzL0LAkvWAXbzqs8OBjdMwrRStF/2U2r8niOr4czbJbNGEp5zkX0oWNTfhlx4YIhcBrG7p+APbiH/9+zTN7hQj4nrbdvW5HwphLhPjx3DiiriJFupar/6ULlcFrbQAAAIAnKK2CC8BK7aQ1RcC4woFnnzlq4t2S766h7Sa/y1nuGUe9lw1wf8If1gc5+z5V9/X/yoWOxFTIxpl0mFeLc67rDR1q47O0LaNM5hwedwNEgfel57tVFGSfc4g1HQcNZRCwIqp0NmKMiesV4F83QML6t7Cf4xSGNvsiqflWaejKoA== test key"

ECDSA_PRIVATE_KEY = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSNVPNs8X0EyvLWfdnKOwjgcdFoCX62
pR9FP4rkml+fhgV+kLumvWPM5kqJPg/oIFmWzLIH/8B9VOX54wunQhSlAAAAsF423b1eNt
29AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI1U82zxfQTK8tZ9
2co7COBx0WgJfralH0U/iuSaX5+GBX6Qu6a9Y8zmSok+D+ggWZbMsgf/wH1U5fnjC6dCFK
UAAAAgDcQG8VMOeZFwRszg7LuisLPob/E/exTG6qP3Ui6gikAAAAAXam9uYXNAam9uYXMt
bGFwdG9wLWFyY2gB
-----END OPENSSH PRIVATE KEY-----"""
ECDSA_PUBLIC_KEY = b"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI1U82zxfQTK8tZ92co7COBx0WgJfralH0U/iuSaX5+GBX6Qu6a9Y8zmSok+D+ggWZbMsgf/wH1U5fnjC6dCFKU= test key"

ED25519_PRIVATE_KEY = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACA4BINHYq2CdcUVdxJDxV0BO4WDLN3LpmPKgcxBP9V5OAAAAKBAQNV/QEDV
fwAAAAtzc2gtZWQyNTUxOQAAACA4BINHYq2CdcUVdxJDxV0BO4WDLN3LpmPKgcxBP9V5OA
AAAEB1RuXH3SfuCupcH/goswX0qZRNZQUpAshd4sNXEH5JrjgEg0dirYJ1xRV3EkPFXQE7
hYMs3cumY8qBzEE/1Xk4AAAAF2pvbmFzQGpvbmFzLWxhcHRvcC1hcmNoAQIDBAUG
-----END OPENSSH PRIVATE KEY-----"""
ED25519_PUBLIC_KEY = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDgEg0dirYJ1xRV3EkPFXQE7hYMs3cumY8qBzEE/1Xk4 test key"


# Private key, encrypted with passphrase 'test'
ENCRYPTED_RSA_KEY = b"""-----BEGIN OPENSSH PRIVATE KEY-----
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
MCWgKOTkI/WNYjDGoOzk1oQhSoY=
-----END OPENSSH PRIVATE KEY-----"""


def test_load_rsa_key():
    # load private key with self-made function
    private_key: rsa.RSAPrivateKey = load_openssh_private_key(RSA_PRIVATE_KEY)
    assert isinstance(private_key, rsa.RSAPrivateKey)

    # load public key separately from string (from ssh-keygen)
    public_key: rsa.RSAPublicKey = load_ssh_public_key(
        RSA_PUBLIC_KEY, backend=default_backend()
    )

    # compare public numbers
    assert (
        private_key.public_key().public_numbers()
        == public_key.public_numbers()
    )


def test_load_dsa_key():
    # load private key with self-made function
    private_key: dsa.DSAPrivateKey = load_openssh_private_key(DSA_PRIVATE_KEY)
    assert isinstance(private_key, dsa.DSAPrivateKey)

    # load public key separately from string (from ssh-keygen)
    public_key: dsa.DSAPublicKey = load_ssh_public_key(
        DSA_PUBLIC_KEY, backend=default_backend()
    )

    # compare public numbers
    assert (
        private_key.public_key().public_numbers()
        == public_key.public_numbers()
    )


def test_load_ecdsa_key():
    private_key: ec.EllipticCurvePrivateKey = load_openssh_private_key(
        ECDSA_PRIVATE_KEY
    )
    assert isinstance(private_key, ec.EllipticCurvePrivateKey)

    # load public key separately from string (from ssh-keygen)
    public_key: ec.EllipticCurvePublicKey = load_ssh_public_key(
        ECDSA_PUBLIC_KEY, backend=default_backend()
    )

    # compare public numbers
    assert (
        private_key.public_key().public_numbers()
        == public_key.public_numbers()
    )


def test_load_ed25519_key():
    private_key: ed25519.Ed25519PrivateKey = load_openssh_private_key(
        ED25519_PRIVATE_KEY
    )
    assert isinstance(private_key, ed25519.Ed25519PrivateKey)

    # load public key separately from string (from ssh-keygen)
    public_key: ec.EllipticCurvePublicKey = load_ssh_public_key(
        ED25519_PUBLIC_KEY, backend=default_backend()
    )

    # compare public numbers
    encoding = Encoding.OpenSSH
    format = PublicFormat.OpenSSH
    assert private_key.public_key().public_bytes(
        encoding, format
    ) == public_key.public_bytes(encoding, format)


def test_load_encrypted_key():
    password = b"test"
    private_key: rsa.RSAPrivateKey = load_openssh_private_key(
        ENCRYPTED_RSA_KEY, passphrase=password
    )
    assert isinstance(private_key, rsa.RSAPrivateKey)


def test_load_encrypted_key_wrong_password():
    password = b"wrong_passphrase"
    with raises(WrongPassphrase):
        load_openssh_private_key(ENCRYPTED_RSA_KEY, passphrase=password)
