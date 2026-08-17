"""Sphinx configuration for the Health-DeID documentation."""

from __future__ import annotations

import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from health_deid import __version__  # noqa: E402

project = "Health-DeID"
author = "Omid Jafari"
copyright = "2026, Omid Jafari"  # noqa: A001
version = __version__
release = __version__

needs_sphinx = "9.1"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosectionlabel",
    "sphinx.ext.githubpages",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
]

exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

autodoc_class_signature = "separated"
autodoc_member_order = "bysource"
autodoc_preserve_defaults = True
autodoc_typehints = "description"
autosectionlabel_prefix_document = True

napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_use_param = True
napoleon_use_rtype = True

html_theme = "furo"
html_title = f"{project} {release}"
html_show_sphinx = False
