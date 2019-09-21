from .rsa import RSAPublicKey

PUBLIC_KEY = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDuprrgTYA9vv5Tl9JutkawBWsvgXaCB7VgmiPYFodQV6Lp/BeYfMRID7OsI2s+QFFSIwUMYFWsNzUPACChkXz0iTiPF3pON9FnvvPbhcPYZGJl+wmNJ1r9aB09w2cbgXSESn4dzIhxo/uXrWtClZlDtpVKknGshRanP2oQCS04ew== test key"


def test_fingerprint():
    key = RSAPublicKey.from_ssh_public_key(PUBLIC_KEY)
    assert (
        key.fingerprint("MD5")
        == "MD5:d4:78:51:9c:ba:fe:28:8d:3f:98:ef:8e:f3:94:b6:59"
    )
    assert (
        key.fingerprint_line("MD5")
        == "1024 MD5:d4:78:51:9c:ba:fe:28:8d:3f:98:ef:8e:f3:94:b6:59 age (RSA)"
    )
    assert (
        key.fingerprint("SHA256")
        == "SHA256:vHkzEqesZd0/v84gmumHX/W8Pv2wkqfa37fJtHc//ak"
    )
    assert (
        key.fingerprint_line("SHA256")
        == "1024 SHA256:vHkzEqesZd0/v84gmumHX/W8Pv2wkqfa37fJtHc//ak age (RSA)"
    )
