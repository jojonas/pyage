# -*- coding: utf-8 -*-
"""Packaging logic for age."""
import fnmatch
import os
import sys

import setuptools

import versioneer

exclude = ["*.*_test", "*.test_*"]


cmdclass = versioneer.get_cmdclass()
versioneer_build_py = cmdclass["build_py"]

# Setuptools does not allow excluding certain Python modules (= Python files) from distribution
# builds (bdist, bdist_wheel). The following snippet filters the included packages/modules. The
# "exclude" list defined above contains exclusion patterns that are applied to
# "packagename.modulename".
#
# Idea from: https://stackoverflow.com/a/50592100


class filtered_build_py(versioneer_build_py):  # type: ignore
    def find_package_modules(self, package, package_dir):
        modules = super().find_package_modules(package, package_dir)
        return [
            (pkg, mod, file,)
            for (pkg, mod, file,) in modules
            if not any(fnmatch.fnmatchcase(pkg + "." + mod, pat=pattern) for pattern in exclude)
        ]


cmdclass["build_py"] = filtered_build_py

# add the src directory to PYTHONPATH so we can import the version
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))  # noqa

setuptools.setup(version=versioneer.get_version(), cmdclass=cmdclass)
