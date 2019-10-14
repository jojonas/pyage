import os
import os.path
import sys

IS_SPHINX = (
    os.path.basename(sys.argv[0]).startswith("sphinx-build")
    or ("sphinx" in sys.modules)
    or os.environ.get("READTHEDOCS", False)
)
