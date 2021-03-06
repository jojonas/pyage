# pyage

[![Build and Test](https://github.com/jojonas/pyage/workflows/Build%20and%20Test/badge.svg)](https://github.com/jojonas/pyage/actions?workflow=Build+and+Test)
[![Compatibility Check](https://github.com/jojonas/pyage/workflows/Compatibility%20with%20FiloSottile/age/badge.svg)](https://github.com/jojonas/pyage/actions?workflow=Compatibility%20with%20FiloSottile/age)
[![Documentation Status](https://readthedocs.org/projects/pyage/badge/?version=latest)](https://pyage.readthedocs.io/en/latest/?badge=latest)
![License](https://img.shields.io/github/license/jojonas/pyage)

![pyage screenshot](https://raw.githubusercontent.com/jojonas/pyage/master/docs/source/_static/carbon.png)

pyage is an experimental implementation of @FiloSottile and @Benjojo12 's project "age".
The spec is currently available as seven-page Google doc at [age-encryption.org/v1](https://age-encryption.org/v1).

This project is still work-in-progress.

⚠️ pyage is not intended to be a secure age implementation!
My original intention was to better understand the spec, find mistakes early and provide a redundant implementation for validation. I'm not a cryptographer (IANAC) and did not (yet) find the time to address  implementation-specific security issues (such as DoS attacks or side-channel attacks).

So:
*Use at your own risk.*

## Quick Start
Install from pip:

    pip install age

Generate a key pair:

    mkdir -p ~/.config/age
    pyage generate > ~/.config/age/keys.txt

Encrypt a file:

    pyage encrypt -i hello.txt -o hello.age pubkey:<recipient public key>

Decrypt a file (uses `~/.config/age/keys.txt`):

    pyage decrypt -i hello.age

For a real tutorial, see [the Tutorial section in the documentation](https://pyage.readthedocs.io/en/latest/tutorials.html).

## Documentation
The full documentation can be found at [pyage.readthedocs.io](https://pyage.readthedocs.io/en/latest/index.html).