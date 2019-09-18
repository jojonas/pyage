# pyage

pyage is an experimental implementation of @FiloSottile and @Benjojo12 's project "age".
The spec is currently available as seven-page Google doc at [age-tool.com](https://age-tool.com).

This project is still work-in-progress.

⚠️ pyage is not intended to be a secure age implementation!
My original intention was to better understand the spec, find mistakes early and provide a redundant implementation for validation. I'm not a cryptographer (IANAC) and did not (yet) spend any time on security (e.g. constant-time implementations).

So:
~~Use at your own risk.~~ *Do not use this project!*

## Installation
Install using pipenv:

    $ pipenv install --dev

To remove pipenv installation:

    $ pipenv --rm

## Development
* Enforce PEP8 with [flake8](http://flake8.pycqa.org/en/latest/) and [autopep8](https://github.com/hhatto/autopep8)
* Run unit tests ([pytest](https://docs.pytest.org/en/latest/))
* Hint native types ([Python typing](https://docs.python.org/3/library/typing.html)), enforce with [mypy](http://mypy-lang.org/)

## TODO
* Implement ;)
* Command line interface
* Documentation with [Sphinx](https://www.sphinx-doc.org/en/master/)
