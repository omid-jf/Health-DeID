Development
===========

Create the development environment and run the quality checks with:

.. code-block:: console

   uv sync --locked --group dev
   uv run ruff check src tests docs examples/scripts
   uv run ruff format --check src tests docs examples/scripts
   uv run mypy src
   uv run djlint src/health_deid/ui/templates --lint
   uv run pytest

Build the documentation locally with:

.. code-block:: console

   uv run sphinx-build -W --keep-going -b html docs docs/_build/html

Build and inspect the Python distributions with:

.. code-block:: console

   uv build
   uvx twine check dist/*

The repository workflows run linting, tests on Python 3.12 through 3.14,
documentation builds, package validation, and trusted publishing to TestPyPI
or PyPI.

Code style
----------

Ruff is the source of truth for Python formatting, import ordering, common bug
checks, and complexity limits. Functions are separated by responsibility and
use blank lines between logical phases; blank lines are not inserted before
every loop or condition mechanically. Public interfaces and behavior that is
not evident from the signature receive docstrings. Small private helpers do not
need repetitive docstrings.

The repository includes ``.editorconfig`` and ``.gitattributes`` so editors on
Windows and macOS use consistent indentation, UTF-8, and line endings.
