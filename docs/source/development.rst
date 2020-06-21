.. _development:

Development
===========

Here are some hints for developers looking to contribute to pyage.

Install with Pipenv
-------------------

Pipenv has the advantage that it allows for exact locking of the dependency
versions. This allows developers to replicate a Python environment as accurately
as possible.

Installation:

::

    $ pipenv install --dev

One can then spawn a shell in the virtual environment:

::

    $ pipenv shell

The resulting shell should already have all development tools included (see next section).

Development Tools
-----------------

The following tools may aid the development process:

* `black <https://github.com/psf/black>`_: Enforces a PEP8-like coding style
* `flake8 <https://flake8.pycqa.org/en/latest/>`_: General purpose Python linter
* `isort <https://timothycrosley.github.io/isort/>`_: Sorts imports alphabetically, grouped by origin as suggested in PEP8
* `pytest <https://docs.pytest.org/en/latest/>`_: Unit test framework, extended with coverage statistics
* `mypy <http://mypy-lang.org/>`_: Static type checking using Python's type hints
* `sphinx <https://www.sphinx-doc.org/en/master/>`_: HTML documentation generation from reStructuredText and docstrings
* `versioneer <https://github.com/warner/python-versioneer>`_: Automatically sets package version from Git tags

Running Unit Tests
------------------

Pyage aims to have decent test coverage. For this purpose, almost every file has
a corresponding ``[...]_test.py`` file. As a test framework, *pytest* is used.
Tests can be run as follows:

::

    $ pytest

Automatic Quality Checks for Git Commits
----------------------------------------

Pyage uses `pre-commit <https://pre-commit.com/>`_ in order to automatically
execute some code quality checks on files staged for commit (see file
``.pre-commit-config.yaml``). Assuming pre-commit is installed globally, the
corresponding hooks can be set up with

::

    $ pre-commit install

Note that the Git hooks expect an installation with Pipenv.

Build Documentation Locally
---------------------------

The documentation can be built locally using Sphinx and a Makefile:

::

    $ cd docs
    $ make

The results can be found in the directory ``docs/build``, e.g.
``docs/build/index.html``.