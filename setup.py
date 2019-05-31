import codecs
import os
import re

from setuptools import find_packages, setup


###############################################################################

NAME = "pem"
KEYWORDS = ["pyopenssl", "ssl", "tls", "pem", "cryptography", "twisted"]
PROJECT_URLS = {
    "Documentation": "https://pem.readthedocs.io/",
    "Bug Tracker": "https://github.com/hynek/pem/issues",
    "Source Code": "https://github.com/hynek/pem",
}
CLASSIFIERS = [
    "Development Status :: 5 - Production/Stable",
    "Intended Audience :: Developers",
    "Natural Language :: English",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Programming Language :: Python",
    "Programming Language :: Python :: Implementation :: CPython",
    "Programming Language :: Python :: Implementation :: PyPy",
    "Programming Language :: Python :: 2",
    "Programming Language :: Python :: 2.7",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.4",
    "Programming Language :: Python :: 3.5",
    "Programming Language :: Python :: 3.6",
    "Programming Language :: Python :: 3.7",
    "Topic :: Software Development :: Libraries :: Python Modules",
]
INSTALL_REQUIRES = []
EXTRAS_REQUIRE = {
    "docs": ["sphinx"],
    "tests": ["coverage", "pytest", "certifi", "pretend", "pyopenssl"],
}
EXTRAS_REQUIRE["dev"] = (
    EXTRAS_REQUIRE["tests"]
    + EXTRAS_REQUIRE["docs"]
    + ["twisted[tls]", "pre-commit"]
)
EXTRAS_REQUIRE["azure-pipelines"] = EXTRAS_REQUIRE["tests"] + [
    "pytest-azurepipelines"
]
PACKAGE_DATA = {"pem": ["py.typed"]}


###############################################################################

HERE = os.path.abspath(os.path.dirname(__file__))


def read(*parts):
    """
    Build an absolute path from *parts* and and return the contents of the
    resulting file.  Assume UTF-8 encoding.
    """
    with codecs.open(os.path.join(HERE, *parts), "rb", "utf-8") as f:
        return f.read()


try:
    PACKAGES
except NameError:
    PACKAGES = find_packages(where="src")

try:
    META_PATH
except NameError:
    META_PATH = os.path.join(HERE, "src", NAME, "__init__.py")
finally:
    META_FILE = read(META_PATH)


def find_meta(meta):
    """
    Extract __*meta*__ from META_FILE.
    """
    meta_match = re.search(
        r"^__{meta}__ = ['\"]([^'\"]*)['\"]".format(meta=meta), META_FILE, re.M
    )
    if meta_match:
        return meta_match.group(1)
    raise RuntimeError("Unable to find __{meta}__ string.".format(meta=meta))


URL = find_meta("url")
LONG = (
    read("README.rst")
    + "\n\n"
    + "Release Information\n"
    + "===================\n\n"
    + re.search(
        r"(\d+.\d.\d \(.*?\)\n.*?)\n\n\n----\n\n\n",
        read("CHANGELOG.rst"),
        re.S,
    ).group(1)
    + "\n\n`Full changelog "
    + "<{url}en/stable/changelog.html>`_.\n\n".format(url=URL)
    + read("AUTHORS.rst")
)

if __name__ == "__main__":
    setup(
        name=NAME,
        description=find_meta("description"),
        license=find_meta("license"),
        url=URL,
        project_urls=PROJECT_URLS,
        version=find_meta("version"),
        author=find_meta("author"),
        author_email=find_meta("email"),
        maintainer=find_meta("author"),
        maintainer_email=find_meta("email"),
        long_description=LONG,
        long_description_content_type="text/x-rst",
        keywords=KEYWORDS,
        packages=PACKAGES,
        package_dir={"": "src"},
        package_data=PACKAGE_DATA,
        include_package_data=True,
        zip_safe=False,
        classifiers=CLASSIFIERS,
        install_requires=INSTALL_REQUIRES,
        extras_require=EXTRAS_REQUIRE,
    )
