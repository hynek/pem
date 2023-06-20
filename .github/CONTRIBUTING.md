# How To Contribute

First off, thank you for considering contributing to *pem*!
It's people like *you* who make it is such a great tool for everyone.

This document is mainly to help you to get started by codifying tribal knowledge and expectations and make it more accessible to everyone.
But don't be afraid to open half-finished PRs and ask questions if something is unclear!

## Workflow

- No contribution is too small!
  Please submit as many fixes for typos and grammar bloopers as you can!
- Try to limit each pull request to *one* change only.
- Since we squash on merge, it's up to you how you handle updates to the main branch.
  Whether you prefer to rebase on main or merge main into your branch, do whatever is more comfortable for you.
- *Always* add tests and docs for your code.
  This is a hard rule; patches with missing tests or documentation can't be merged.
- Consider updating CHANGELOG.rst to reflect the changes as observed by people using this library.
- Make sure your changes pass our [CI].
  You won't get any feedback until it's green unless you ask for it.
- Once you've addressed review feedback, make sure to bump the pull request with a short note, so we know you're done.
- Don’t break [backward compatibility].

## Code

- Obey [PEP 8] and [PEP 257].
  We use the `"""`-on-separate-lines style for docstrings:

  ```python
  def func(x):
      """
      Do something.

      :param str x: A very important parameter.

      :rtype: str
      """
  ```

- If you add or change public APIs, tag the docstring using `..  versionadded:: 16.0.0 WHAT` or `..  versionchanged:: 17.1.0 WHAT`.

- We use [isort] to sort our imports, and we follow the [Black] code style with a line length of 79 characters.
  As long as you run our full tox suite before committing, or install our [pre-commit] hooks (ideally you'll do both -- see below "Local Development Environment"), you won't have to spend any time on formatting your code at all.
  If you don't, CI will catch it for you -- but that seems like a waste of your time!

## Tests

- Write your asserts as `expected == actual` to line them up nicely and leave an empty line before them:

  ```
  .. code-block:: python
  ```

  > x = f()
  >
  > assert 42 == x.some_attribute
  > assert "foo" == x.\_a_private_attribute

- To run the test suite, all you need is a recent [tox].
  It will ensure the test suite runs with all dependencies against all Python versions just as it will in our CI.
  If you lack some Python versions, you can can make it a non-failure using `tox --skip-missing-interpreters` (in that case you may want to look into [asdf] or [pyenv] that make it very easy to install many different Python versions in parallel).

- Write [good test docstrings].

## Documentation

- Use [semantic newlines] in [reStructuredText] files (files ending in `.rst`):

  ```rst
  This is a sentence.
  This is another sentence.
  ```

- If you start a new section, add two blank lines before and one blank line after the header except if two headers follow immediately after each other:

  ```rst
  Last line of previous section.


  Header of New Top Section
  -------------------------

  Header of New Section
  ^^^^^^^^^^^^^^^^^^^^^

  First line of new section.
  ```

- If your change is noteworthy, add an entry to the [changelog].
  Use [semantic newlines], and add a link to your pull request:

  ```rst
  - Added ``pem.func()`` that does foo.
    It's pretty cool.
    `#1 <https://github.com/hynek/pem/pull/1>`_
  - ``pem.func()`` now doesn't crash the Large Hadron Collider anymore.
    That was a nasty bug!
    `#2 <https://github.com/hynek/pem/pull/2>`_
  ```

## Local Development Environment

You can (and should) run our test suite using [tox].
However, you’ll probably want a more traditional environment as well.
We highly recommend to develop using the version specified in the `.python-version` file in the project root.
That's the version used in CI by default.

First create a [virtual environment](https://virtualenv.pypa.io/).
It’s out of scope for this document to list all the ways to manage virtual environments in Python, but if you don’t already have a pet way, take some time to look at tools like [pew](https://github.com/berdario/pew), [virtualfish](https://virtualfish.readthedocs.io/), [virtualenvwrapper](https://virtualenvwrapper.readthedocs.io/), and direnv's [Python support](https://github.com/direnv/direnv/wiki/Python).

Next get an up to date checkout of the *pem* repository:

```bash
git clone git@github.com:hynek/pem.git
```

Change into the newly created directory and **after activating your virtual environment** install an editable version of *pem* along with its tests and docs requirements:

```bash
cd pem
pip install -e .[dev]
```

At this point,

```bash
$ python -m pytest
```

should work.

When working on the documentation, use:

```bash
$ tox -e docs-serve
```

To watch your files and repeatedly build.
And use:

```bash
$ tox -e docs
```

To build it once and run our doctests.

The built documentation can then be found in `docs/_build/html/`.

To avoid committing code that violates our style guide, we strongly advice you to install [pre-commit] [^f1] hooks:

```bash
$ pre-commit install
```

You can also run them anytime (as our tox does) using:

```bash
$ pre-commit run --all-files
```

[^f1]: pre-commit should have been installed into your virtualenv automatically when you ran `pip install -e .[dev]` above. If pre-commit is missing, it may be that you need to re-run `pip install -e .[dev]`.

______________________________________________________________________

Again, this list is mainly to help you to get started by codifying tribal knowledge and expectations.
If something is unclear, feel free to ask for help!

Please note that this project is released with a Contributor [Code of Conduct].
By participating in this project you agree to abide by its terms.
Please report any harm to [Hynek Schlawack] in any way you find appropriate.

Thank you for considering contributing to *pem*!

[asdf]: https://asdf-vm.com/
[backward compatibility]: https://pem.readthedocs.io/en/latest/backward-compatibility.html
[black]: https://github.com/psf/black
[changelog]: https://github.com/hynek/pem/blob/main/CHANGELOG.rst
[ci]: https://github.com/hynek/pem/actions
[code of conduct]: https://github.com/hynek/pem/blob/main/.github/CODE_OF_CONDUCT.rst
[good test docstrings]: https://jml.io/test-docstrings/
[hynek schlawack]: https://hynek.me/about/
[isort]: https://github.com/PyCQA/isort
[pep 257]: https://www.python.org/dev/peps/pep-0257/
[pep 8]: https://www.python.org/dev/peps/pep-0008/
[pre-commit]: https://pre-commit.com/
[pyenv]: https://github.com/pyenv/pyenv
[restructuredtext]: https://www.sphinx-doc.org/en/master/usage/restructuredtext/basics.html
[semantic newlines]: https://rhodesmill.org/brandon/2012/one-sentence-per-line/
[tox]: https://tox.readthedocs.io/
