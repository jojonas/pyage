import os
import os.path
import sys


def is_sphinx():
    return (
        os.path.basename(sys.argv[0]).startswith("sphinx-build")
        or ("sphinx" in sys.modules)
        or os.environ.get("READTHEDOCS", False)
    )
