from setuptools import setup

setup(
    name="pyage",
    version="0.1",
    description="Experimental python implementation age-tool.com",
    author="Jonas Lieb",
    author_email="",
    url="https://github.com/jojonas/pyage",
    packages=["age"],
    scripts=["age"],
    install_requires=[],  # handled by pipenv (?)
)
