# -*- coding: utf-8 -*-
"""Packaging logic for age."""
import fnmatch
import os
import sys

import setuptools

from setuptools.command.build_py import build_py as build_py_orig

exclude = ["*.*_test", "*.test_*"]

# Setuptools does not allow excluding certain Python modules (= Python files) from distribution
# builds (bdist, bdist_wheel). The following snippet filters the included packages/modules. The
# "exclude" list defined above contains exclusion patterns that are applied to
# "packagename.modulename".
#
# Idea from: https://stackoverflow.com/a/50592100


class build_py(build_py_orig):
    def find_package_modules(self, package, package_dir):
        modules = super().find_package_modules(package, package_dir)
        return [
            (pkg, mod, file,)
            for (pkg, mod, file,) in modules
            if not any(fnmatch.fnmatchcase(pkg + "." + mod, pat=pattern) for pattern in exclude)
        ]


# add the src directory to PYTHONPATH so we can import the version
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))  # noqa

if __name__ == "__main__":
    setuptools.setup(cmdclass={"build_py": build_py},)
