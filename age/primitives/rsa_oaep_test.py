import os

from age.keys import RSAPrivateKey, RSAPublicKey
from .rsa_oaep import rsa_encrypt, rsa_decrypt

# 1024bit RSA keypair generated using ssh-keygen

TEST_PRIVATE_KEY = b"""-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
"""

TEST_PUBLIC_KEY = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDuprrgTYA9vv5Tl9JutkawBWsvgXaCB7VgmiPYFodQV6Lp/BeYfMRID7OsI2s+QFFSIwUMYFWsNzUPACChkXz0iTiPF3pON9FnvvPbhcPYZGJl+wmNJ1r9aB09w2cbgXSESn4dzIhxo/uXrWtClZlDtpVKknGshRanP2oQCS04ew== public key for unit tests"


def test_rsa():
    data = os.urandom(16)
    label = b"secret data"

    private_key = RSAPrivateKey.from_pem(TEST_PRIVATE_KEY)
    public_key = RSAPublicKey.from_ssh_public_key(TEST_PUBLIC_KEY)

    encrypted = rsa_encrypt(public_key, label, data)
    assert encrypted

    decrypted = rsa_decrypt(private_key, label, encrypted)
    assert decrypted
    assert decrypted == data
