import collections
import glob
import os.path
import re
import typing

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ed25519 as crypto_ed25519
from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from age.keys.agekey import AgePrivateKey, AgePublicKey
from age.keys.base import DecryptionKey, EncryptionKey
from age.keys.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from age.keys.rsa import RSAPrivateKey, RSAPublicKey
from age.openssh_keys import InvalidKeyFile, load_openssh_private_key


def load_keys_txt(filename="~/.config/age/keys.txt") -> typing.List[DecryptionKey]:
    filename = os.path.expanduser(filename)

    if not os.path.isfile(filename):
        return []

    keys = []

    with open(filename, "r") as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith("#"):
                # ignore comments
                continue

            key = AgePrivateKey.from_private_string(line)
            keys.append(key)

    return keys


def load_ssh_private_key(filename, password=None) -> typing.Optional[DecryptionKey]:
    filename = os.path.expanduser(filename)

    if not os.path.isfile(filename):
        return None

    with open(filename, "rb") as file:
        pem_data = file.read()

    try:
        private_key = load_pem_private_key(pem_data, password=password, backend=default_backend())
    except ValueError:
        try:
            # OpenSSH private keys are special snowflakes
            private_key = load_openssh_private_key(pem_data, passphrase=password)
        except InvalidKeyFile:
            return None

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


AliasDict = typing.Dict[str, typing.List[str]]


def load_aliases(filename="~/.config/age/aliases.txt") -> AliasDict:
    aliases: AliasDict = collections.defaultdict(list)

    filename = os.path.expanduser(filename)

    if os.path.isfile(filename):
        with open(filename, "r") as file:
            for line in file:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                label, _, values = line.partition(":")
                public_keys = values.split()
                aliases[label].extend(public_keys)

    return dict(aliases)


def resolve_public_key(
    keystr: str, aliases: AliasDict = None, read_aliases=True, read_files=True, read_urls=True
) -> typing.List[EncryptionKey]:
    # none of the key types like leading/trailing whitespace
    keystr = keystr.strip()

    # First: resolve aliases
    if read_aliases and aliases is not None and keystr in aliases:
        resolved_from_alias: typing.List[EncryptionKey] = []
        for alias in aliases[keystr]:
            resolved_alias = resolve_public_key(alias)
            if not resolved_alias:
                raise ValueError(f"Could not resolve alias {alias}")
            resolved_from_alias.extend(resolved_alias)
        return resolved_from_alias

    # resolve "github:" links
    if keystr.startswith("github:"):
        _, _, username = keystr.partition(":")
        github_url = f"https://github.com/{username}.keys"
        return resolve_public_key(github_url)

    # resolve files
    if read_files and os.path.isfile(keystr):
        resolved_from_file: typing.List[EncryptionKey] = []
        with open(keystr, "r") as file:
            for line in file:
                resolved_from_file.extend(
                    resolve_public_key(line, read_aliases=False, read_files=False, read_urls=False)
                )
        return resolved_from_file

    # resolve URLs
    if read_urls and re.match("^https?://", keystr):
        resolved_from_url: typing.List[EncryptionKey] = []
        response = requests.get(keystr)
        response.raise_for_status()
        for line in response.text.splitlines():
            resolved_from_url.extend(
                resolve_public_key(line, read_aliases=False, read_files=False, read_urls=False)
            )
        return resolved_from_url

    # resolve "pubkey:" lines
    if keystr.startswith(AgePublicKey.PUBLIC_KEY_BECH32_HRP):
        return [AgePublicKey.from_public_string(keystr)]

    # resolve "ssh-rsa" lines
    if keystr.startswith("ssh-rsa"):
        return [RSAPublicKey.from_ssh_public_key(keystr.encode("utf-8"))]

    # resolve "ecdsa-" lines
    if keystr.startswith("ssh-ed25519"):
        return [Ed25519PublicKey.from_ssh_public_key(keystr.encode("utf-8"))]

    return []
