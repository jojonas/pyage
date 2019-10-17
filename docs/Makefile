# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line, and also
# from the environment for the first two.
SPHINXOPTS    ?=
SPHINXBUILD   ?= sphinx-build
SPHINXAPIDOC  ?= sphinx-apidoc
SOURCEDIR     = source
BUILDDIR      = build
MODULEDIR	  = ../src/age

PYTHON_FILES  = $(shell find $(MODULEDIR) -type f -name '*.py')

.DEFAULT_GOAL := all

all: html ../requirements.txt

.PHONY: Makefile

# Apidoc: automatically generate everything in source/api
apidoc: $(PYTHON_FILES)
	rm -rf $(SOURCEDIR)/api/*.rst
	$(SPHINXAPIDOC) -f --ext-todo --ext-autodoc -o "$(SOURCEDIR)/api" "$(MODULEDIR)" "$(MODULEDIR)/**/*_test.py" "$(MODULEDIR)/*_test.py"

# Requirements.txt (for RTD)
../requirements.txt: $(PYTHON_FILES)
	cd .. && pipenv_to_requirements -f

# Build HTML files
html: apidoc Makefile
	$(SPHINXBUILD) -T -b $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS)

clean:
	rm -rf $(SOURCEDIR)/api/*.rst
	rm -rf $(BUILDDIR)
	mkdir -p $(BUILDDIR)
	rm -rf ../requirements.txt
	rm -rf ../requirements-dev.txt
