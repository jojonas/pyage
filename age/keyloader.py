import collections
import glob
import os.path
import typing


from cryptography.hazmat.primitives.serialization import (
    load_ssh_public_key,
    load_pem_private_key,
)
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.asymmetric import ed25519 as crypto_ed25519
from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa

from age.keys import AgePrivateKey, RSAPrivateKey, Ed25519PrivateKey
from age.keys.base import DecryptionKey
from age.openssh_keys import load_openssh_private_key


def load_keys_txt(
    filename="~/.config/age/keys.txt"
) -> typing.Collection[DecryptionKey]:

    filename = os.path.expanduser(filename)

    keys = []

    with open(filename, "r") as file:
        for line in file:
            line = line.strip()
            if line.startswith("#"):
                # ignore comments
                continue

            key = AgePrivateKey.from_private_string(line)
            keys.append(key)

    return keys


def load_ssh_private_key(
    filename, password=None
) -> typing.Optional[DecryptionKey]:
    with open(filename, "rb") as file:
        pem_data = file.read()

    try:
        private_key = load_pem_private_key(
            pem_data, password=password, backend=default_backend()
        )
    except ValueError:
        # OpenSSH private keys are special snowflakes
        private_key = load_openssh_private_key(pem_data, passphrase=password)

    if isinstance(private_key, crypto_rsa.RSAPrivateKey):
        return RSAPrivateKey(private_key)
    elif isinstance(private_key, crypto_ed25519.Ed25519PrivateKey):
        return Ed25519PrivateKey(private_key)

    return None


def load_ssh_keys(root="~/.ssh") -> typing.Collection[DecryptionKey]:
    root = os.path.expanduser(root)

    keys = []

    for filename in glob.glob(os.path.join(root, "id_*")):
        key = load_ssh_private_key(filename)
        if key:
            keys.append(key)

    return keys


def load_aliases(
    filename="~/.config/age/aliases.txt"
) -> typing.Dict[str, typing.Collection[str]]:
    aliases = collections.defaultdict(list)

    with open(filename, "r") as file:
        for line in file:
            line = line.strip()
            if line.startswith("#"):
                continue

            label, _, values = line.split(":")
            public_keys = values.split()
            aliases[label].append(public_keys)

    return dict(aliases)
