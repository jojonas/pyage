# pyage

[![Build and Test](https://github.com/jojonas/pyage/workflows/Build%20and%20Test/badge.svg)](https://github.com/jojonas/pyage/actions?workflow=Build+and+Test)
[![Compatibility Check](https://github.com/jojonas/pyage/workflows/Compatibility%20with%20FiloSottile/age/badge.svg)](https://github.com/jojonas/pyage/actions?workflow=Compatibility%20with%20FiloSottile/age)
[![Documentation Status](https://readthedocs.org/projects/pyage/badge/?version=latest)](https://pyage.readthedocs.io/en/latest/?badge=latest)
![License](https://img.shields.io/github/license/jojonas/pyage)

![pyage screenshot](https://raw.githubusercontent.com/jojonas/pyage/master/docs/source/_static/carbon.png)

pyage is an experimental implementation of @FiloSottile and @Benjojo12 's project "age".
The spec is currently available as seven-page Google doc at [age-tool.com](https://age-tool.com).

This project is still work-in-progress.

⚠️ pyage is not intended to be a secure age implementation!
My original intention was to better understand the spec, find mistakes early and provide a redundant implementation for validation. I'm not a cryptographer (IANAC) and did not (yet) spend any time on security (e.g. constant-time implementations).

So:
~~Use at your own risk.~~ *Do not use this project!*

## Quick Start
Install using pipenv:

    $ pipenv install

Generate a key pair:

    $ mkdir -p ~/.config/age
    $ pipenv run age generate > ~/.config/age/keys.txt

Encrypt a file:

    $ pipenv run age encrypt -i hello.txt -o hello.age pubkey:<recipient public key>

Decrypt a file (uses `~/.config/age/keys.txt`):

    $ pipenv run age decrypt -i hello.age

For a real tutorial, see [the Tutorial section in the documentation](https://pyage.readthedocs.io/en/latest/tutorials.html).

## Documentation
The full documentation can be found at [pyage.readthedocs.io](https://pyage.readthedocs.io/en/latest/index.html).

## Development
* Enforce PEP8 with [black](https://github.com/psf/black), [flake8](http://flake8.pycqa.org/en/latest/) and [isort](https://timothycrosley.github.io/isort/)
* Run unit tests ([pytest](https://docs.pytest.org/en/latest/)) with coverage testing
* Hint native types ([Python typing](https://docs.python.org/3/library/typing.html)), enforce with [mypy](http://mypy-lang.org/)
* Documentation with [Sphinx](https://www.sphinx-doc.org/en/master/), pushed to [pyage.readthedocs.io](https://pyage.readthedocs.io/en/latest/index.html)

## TODO
* Error handling
* Proper logging (to stderr)
