#!/usr/bin/env python3

import io
import os
import stat
import sys
import typing
from datetime import datetime

import click

from age import __version__ as age_version
from age.file import Decryptor, Encryptor
from age.keyloader import load_aliases, load_keys_txt, load_ssh_keys, resolve_public_key
from age.keys.agekey import AgePrivateKey
from age.keys.base import DecryptionKey
from age.keys.password import PasswordKey
from age.utils.asciiarmor import AGE_PEM_LABEL, AsciiArmoredInput, AsciiArmoredOutput
from age.utils.copy_doc import copy_doc


def encrypt(
    recipients: typing.List[str] = None,
    infile: typing.BinaryIO = None,
    outfile: typing.BinaryIO = None,
    ask_password: bool = False,
    ascii_armored: bool = False,
) -> None:
    """Encrypt data for the given recipients.

    \b
    RECIPIENTS can be a list of either:
    - aliases (from ~/.config/age/aliases.txt)
    - age public keys (starting with "age1...")
    - SSH public keys (starting with "ssh-rsa" or "ssh-ed25519")
    - Files with one key per line (no aliases allowed)
    - URLs to files with one key per line (no aliases allowed)
    - GitHub usernames (will fetch SSH public keys from https://github.com/USERNAME.keys)

    Plaintext data can be passed via the standard input stream or from a file.
    Encryption to the standard output stream is only allowed if the stream
    is not bound to a TTY, in any case an output file can be used.

    A password recipient can be added with the '-p' option. age will prompt
    for the password.

    Note that in this case, anyone in possession of the password can tamper
    with the message, therefore it is recommended to not mix password- and
    public key recipients.

    """

    if not infile:
        infile = sys.stdin.buffer
    if not outfile:
        outfile = sys.stdout.buffer
    if not recipients:
        recipients = []

    if outfile is sys.stdout.buffer and sys.stdout.isatty():
        print("Refusing to encrypt to a TTY.", file=sys.stderr)
        sys.exit(1)

    aliases = load_aliases()

    keys = []
    for recipient in recipients:
        keys.extend(resolve_public_key(recipient, aliases=aliases))

    if ask_password:
        if recipients:
            print(
                "Using password recipient in addition to public keys. "
                + "Note that anyone in possession of the password can tamper with "
                + "the message content and recipient list.",
                file=sys.stderr,
            )
        password = click.prompt("Type passphrase", hide_input=True).encode("utf-8")
        keys.append(PasswordKey(password))

    if not keys:
        print("You must specify at least one recipient.", file=sys.stderr)
        sys.exit(1)

    if ascii_armored:
        # ignoring mypy error because RawIOBase satisfies BinaryIO (doesn't it?)
        outfile = AsciiArmoredOutput(AGE_PEM_LABEL, outfile)  # type: ignore

    with Encryptor(keys, outfile) as encryptor:
        encryptor.write(infile.read())


def decrypt(
    infile: typing.BinaryIO = None,
    outfile: typing.BinaryIO = None,
    ask_password: bool = False,
    keyfiles: typing.List[str] = None,
    ascii_armored: bool = False,
) -> None:
    """Decrypt a file encrypted with 'age encrypt'.

    Ciphertext can be passed from the standard input stream and from a file.
    Plaintext will by default be written to the standard output stream, but
    a filename can be specified.

    \b
    Decryption is attempted with keys from the following locations:
    - Age private keys from 'age generate' in file ~/.config/age/keys.txt
    - Private SSH keys at ~/.ssh/id_*
    - Age private keys in files passed via KEYFILES.

    If the '-p' switch is provided, age will prompt for a password and also
    attempt to decrypt the message with the given password.
    """

    if not infile:
        infile = sys.stdin.buffer
    if not outfile:
        outfile = sys.stdout.buffer
    if not keyfiles:
        keyfiles = []

    keys: typing.List[DecryptionKey] = []
    keys.extend(load_keys_txt())
    keys.extend(load_ssh_keys())
    for keyfile in keyfiles:
        keys.extend(load_keys_txt(keyfile))

    if ask_password:
        password = click.prompt("Type passphrase", hide_input=True).encode("utf-8")
        keys.append(PasswordKey(password))

    if not keys:
        print("No keys loaded.", file=sys.stderr)
        sys.exit(1)

    if ascii_armored:
        # ignoring mypy error because RawIOBase satisfies BinaryIO (doesn't it?)
        infile = AsciiArmoredInput(AGE_PEM_LABEL, infile)  # type: ignore

    with Decryptor(keys, infile) as decryptor:
        outfile.write(decryptor.read())


def generate(outfile: typing.TextIO = None) -> None:
    """Generate a new age private/public key pair.

    If no FILENAME is given, the command outputs the key pair to the standard output stream.

    If FILENAME exists, age will warn if the file permissions allow others to read, write or
    execute the file.
    """

    if not outfile:
        outfile = sys.stdout

    key = AgePrivateKey.generate()

    now = datetime.now()
    outfile.write(f"# created: {now:%Y-%m-%dT%H:%M:%S}\n")
    outfile.write("# " + key.public_key().public_string() + "\n")
    outfile.write(key.private_string() + "\n")

    # check permissions if the key is stored in a file
    try:
        stat_result = os.stat(outfile.fileno())
    except io.UnsupportedOperation:
        pass
    else:
        mode = stat_result[stat.ST_MODE]
        if mode & stat.S_IFREG and (mode & stat.S_IRWXO or mode & stat.S_IRWXG):
            perms = mode & 0o777
            print(
                f"Warning: The file permissions ({perms:o}) indicate that other users may have access to the output.",
                file=sys.stderr,
            )

    # print public key to stderr if:
    # - data is going to a file
    # OR: - data is not going to a tty (e.g. piped)
    if (outfile is not sys.stdout) or (not sys.stdout.isatty()):
        print("Public key: " + key.public_key().public_string(), file=sys.stderr)


@click.group()
@click.version_option(version=age_version)
def main():
    pass


@main.command("encrypt")
@click.option("-i", "--infile", type=click.File("rb"))
@click.option("-o", "--outfile", type=click.File("wb"))
@click.option("-p", "--password", is_flag=True)
@click.option("-a", "--ascii", is_flag=True)
@click.argument("recipients", nargs=-1)
@copy_doc(encrypt)
def cli_encrypt(infile, outfile, password, ascii, recipients):
    return encrypt(
        recipients=recipients,
        infile=infile,
        outfile=outfile,
        ask_password=password,
        ascii_armored=ascii,
    )


@main.command("decrypt")
@click.option("-i", "--infile", type=click.File("rb"))
@click.option("-o", "--outfile", type=click.File("wb"))
@click.option("-p", "--password", is_flag=True)
@click.option("-a", "--ascii", is_flag=True)
@click.argument("keyfiles", nargs=-1)
@copy_doc(decrypt)
def cli_decrypt(infile, outfile, password, ascii, keyfiles):
    return decrypt(
        infile=infile,
        outfile=outfile,
        ask_password=password,
        keyfiles=keyfiles,
        ascii_armored=ascii,
    )


@main.command("generate")
@click.option("-o", "--outfile", type=click.File("w"), help="Keypair destination")
@copy_doc(generate)
def cli_generate(outfile):
    return generate(outfile=outfile)


if __name__ == "__main__":
    main()
