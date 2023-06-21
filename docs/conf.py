# SPDX-FileCopyrightText: 2013 Hynek Schlawack <hs@ox.cx>
#
# SPDX-License-Identifier: MIT

from importlib import metadata


linkcheck_ignore = [
    r"https://github.com/.*/(issues|pull)/\d+",
]

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.doctest",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "notfound.extension",
    "myst_parser",
]

myst_enable_extensions = [
    "colon_fence",
    "smartquotes",
    "deflist",
]

# Move type hints into the description block, instead of the func definition.
autodoc_typehints = "description"
autodoc_typehints_description_target = "documented"

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# The suffix(es) of source filenames.
source_suffix = [".rst", ".md"]

# The master toctree document.
master_doc = "index"

project = "pem"
author = "Hynek Schlawack"
copyright = "2013, " + author

release = metadata.version("pem")
version = release.rsplit(".", 1)[0]
if "dev" in release:
    release = version = "UNRELEASED"

language = "en"

exclude_patterns = ["_build"]

nitpick_ignore = [
    ("py:class", "twisted.internet._sslverify.OpenSSLCertificateOptions"),
    ("py:class", "ssl.CertificateOptions"),
]

# -- Options for HTML output ----------------------------------------------

html_theme = "furo"
html_theme_options = {
    "source_branch": "main",
    "source_directory": "docs/",
}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = []

# Output file base name for HTML help builder.
htmlhelp_basename = "pemdoc"

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "twisted": (
        "https://docs.twistedmatrix.com/en/stable/",
        None,
    ),
}
