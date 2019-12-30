import os.path
import tempfile

from age.keyloader import (
    load_aliases,
    load_keys_txt,
    load_ssh_keys,
    load_ssh_private_key,
    resolve_public_key,
)
from age.keys.agekey import AgePrivateKey, AgePublicKey
from age.keys.ed25519 import Ed25519PrivateKey
from age.keys.rsa import RSAPrivateKey


def test_keys_txt():
    with tempfile.NamedTemporaryFile() as file:
        file.write(
            b"""# created: 2019-12-30T19:34:52
# age17v86x0glgp0vls0uaru4h3xpfm79xu6ud6ew3cvd3956m96umf5szty0gd
AGE-SECRET-KEY-1FP0QEUKLA2GRCFSEZC9JU6WR8RKWPFKM0P3S8TL9NK7PTHMWNALQT7V9DX"""
        )
        file.flush()

        keys = load_keys_txt(file.name)

    assert len(keys) == 1
    assert isinstance(keys[0], AgePrivateKey)

    assert len(load_keys_txt("doesnotexist")) == 0


def test_ssh_keyload():
    with tempfile.TemporaryDirectory() as directory:
        rsa_path = os.path.join(directory, "id_rsa")
        with open(rsa_path, "wb") as file:
            file.write(
                b"""-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
"""
            )

        ed25519_path = os.path.join(directory, "id_ed25519")
        with open(ed25519_path, "wb") as file:
            file.write(
                b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBGw1K615J4yFGn900mmHaA9hJDhsyyXfe3y8TTNZUTHQAAAKAjfnmzI355
swAAAAtzc2gtZWQyNTUxOQAAACBGw1K615J4yFGn900mmHaA9hJDhsyyXfe3y8TTNZUTHQ
AAAEBVBtfpUEGmiSwPi9nzPH5KA+a1D0YVuBndOuU/tL1alEbDUrrXknjIUaf3TSaYdoD2
EkOGzLJd97fLxNM1lRMdAAAAF2pvbmFzQGpvbmFzLWxhcHRvcC1hcmNoAQIDBAUG
-----END OPENSSH PRIVATE KEY-----"""
            )

        key = load_ssh_private_key(rsa_path)
        assert isinstance(key, RSAPrivateKey)

        key = load_ssh_private_key(ed25519_path)
        assert isinstance(key, Ed25519PrivateKey)

        key = load_ssh_private_key("doesnotexist")
        assert key is None

        empty_path = os.path.join(directory, "id_empty")
        with open(empty_path, "wb") as file:
            file.write(b"\n")

        key = load_ssh_private_key(empty_path)
        assert key is None

        keys = load_ssh_keys(directory)
        assert len(keys) == 2

        assert len(load_ssh_keys("doesnotexist")) == 0


def test_aliases():
    with tempfile.NamedTemporaryFile() as file:
        file.write(
            b"""# this is a comment

filippo: age17v86x0glgp0vls0uaru4h3xpfm79xu6ud6ew3cvd3956m96umf5szty0gd
ben: age17v86x0glgp0vls0uaru4h3xpfm79xu6ud6ew3cvd3956m96umf5szty0gd github:Benjojo"""
        )
        file.flush()

        aliases = load_aliases(file.name)
        assert aliases == {
            "filippo": ["age17v86x0glgp0vls0uaru4h3xpfm79xu6ud6ew3cvd3956m96umf5szty0gd"],
            "ben": [
                "age17v86x0glgp0vls0uaru4h3xpfm79xu6ud6ew3cvd3956m96umf5szty0gd",
                "github:Benjojo",
            ],
        }


def test_public_key_resolving():
    assert resolve_public_key("age17v86x0glgp0vls0uaru4h3xpfm79xu6ud6ew3cvd3956m96umf5szty0gd") == [
        AgePublicKey.from_public_string(
            "age17v86x0glgp0vls0uaru4h3xpfm79xu6ud6ew3cvd3956m96umf5szty0gd"
        )
    ]
    # check here: https://github.com/jojonas.keys
    assert len(resolve_public_key("github:jojonas")) == 4
