import os

from age.utils.env import is_sphinx


def test_is_sphinx():
    assert not is_sphinx()
    os.environ["READTHEDOCS"] = "true"
    assert is_sphinx()
