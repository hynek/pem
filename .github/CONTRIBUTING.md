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
  Whether you prefer to rebase on main or merge `main` into your branch, do whatever is more comfortable for you.
- *Always* add tests and docs for your code.
  This is a hard rule; patches with missing tests or documentation won't be merged.
- Consider updating [CHANGELOG.md][changelog] to reflect the changes as observed by people using this library.
- Make sure your changes pass our [CI].
  You won't get any feedback until it's green unless you ask for it.
- Once you've addressed review feedback, make sure to bump the pull request with a short note, so we know you're done.
- Don’t break [backwards-compatibility].


## Code

- Obey [PEP 8] and [PEP 257].
  We use the `"""`-on-separate-lines style for docstrings:

  ```python
  def func(x: str) -> str:
      """
      Do something.

      Args:
        x: A very important parameter.
      """
  ```

- If you add or change public APIs, tag the docstring using `..  versionadded:: 16.1.0 WHAT` or `..  versionchanged:: 17.1.0 WHAT`.
  We follow CalVer, so the next version will be the current with with the middle number incremented (e.g. `23.1.0` -> `23.2.0`).

- We use [Ruff] to sort our imports, and we follow the [Black] code style with a line length of 79 characters.
  As long as you run our full [*tox*] suite before committing, or install our [*pre-commit*] hooks, you won't have to spend any time on formatting your code at all.
  If you don't, CI will catch it for you -- but that seems like a waste of your time!


## Tests

- Write your asserts as `expected == actual` to line them up nicely and leave an empty line before them:

  ```python
  x = f()

  assert 42 == x.some_attribute
  assert "foo" == x.\_a_private_attribute
  ```

- To run the test suite, all you need is a recent [*tox*].
  It will ensure the test suite runs with all dependencies against all Python versions just as it will in our CI.

- Write [good test docstrings].


## Documentation

- Use [semantic newlines] in Markdown and reStructuredText files (files ending in `.md` and `.rst`):

  ```markdown
  This is a sentence.
  This is another sentence.
  ```

- If you start a new section, add two blank lines before and one blank line after the header except if two headers follow immediately after each other:

  ```markdown
  Last line of previous section.


  ## Header of New Top Section

  ### Header of New Section

  First line of new section.
  ```

- If your change is noteworthy, add an entry to the [changelog].
  Use [semantic newlines], and add a link to your pull request:

  ```markdown
  - Added `pem.func()` that does foo.
    It's pretty cool.
    [#1](https://github.com/hynek/pem/pull/1)
  - `pem.func()` now doesn't crash the Large Hadron Collider anymore.
    That was a nasty bug!
    [#2](https://github.com/hynek/pem/pull/2)
  ```


## Local Development Environment

You can (and should) run our test suite using [*tox*].
However, you’ll probably want a more traditional environment as well.

First, create a [virtual environment](https://virtualenv.pypa.io/) so you don't break your system-wide Python installation.
We recommend using the Python version from the `.python-version` file in the project's root directory.

If you're using [*direnv*](https://direnv.net), you can automate the creation of a virtual environment with the correct Python version by adding the following `.envrc` to the project root:

```bash
layout python python$(cat .python-version)
```

[Create a fork](https://github.com/hynek/pem/fork) of the *pem* repository and clone it:

```console
$ git clone git@github.com:YOU/pem.git
```

Or if you prefer to use Git via HTTPS:

```console
$ git clone https://github.com/YOU/pem.git
```

> **Warning**
> - **Before** you start working on a new pull request, use the "*Sync fork*" button in GitHub's web UI to ensure your fork is up to date.
> - **Always create a new branch off `main` for each new pull request.**
>   Yes, you can work on `main` in your fork and submit pull requests.
>   But this will *inevitably* lead to you not being able to synchronize your fork with upstream and having to start over.

Change into the newly created directory and after activating a virtual environment, install an editable version of *pem* along with its development requirements:

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

... to watch your files and repeatedly build.
And use:

```bash
$ tox -e docs
```

... to build it once and run our doctests.

The built documentation can then be found in `docs/_build/html/`.

To avoid committing code that violates our style guide, we strongly advice you to install [*pre-commit*] and our hooks:

```bash
$ pre-commit install
```

You can also run them anytime (as our *tox* does) using:

```bash
$ pre-commit run --all-files
```

---

Again, this list is mainly to help you to get started by codifying tribal knowledge and expectations.
If something is unclear, feel free to ask for help!

Please note that this project is released with a Contributor [Code of Conduct].
By participating in this project you agree to abide by its terms.
Please report any harm to [Hynek Schlawack] in any way you find appropriate.

Thank you for considering contributing to *pem*!

[backwards-compatibility]: https://github.com/hynek/pem/blob/main/.github/SECURITY.md
[Black]: https://github.com/psf/black
[changelog]: https://github.com/hynek/pem/blob/main/CHANGELOG.md
[ci]: https://github.com/hynek/pem/actions
[code of conduct]: https://github.com/hynek/pem/blob/main/.github/CODE_OF_CONDUCT.md
[good test docstrings]: https://jml.io/test-docstrings/
[hynek schlawack]: https://hynek.me/about/
[pep 257]: https://peps.python.org/pep-0257/
[pep 8]: https://peps.python.org/pep-0008/
[*pre-commit*]: https://pre-commit.com/
[restructuredtext]: https://www.sphinx-doc.org/en/master/usage/restructuredtext/basics.html
[semantic newlines]: https://rhodesmill.org/brandon/2012/one-sentence-per-line/
[*tox*]: https://tox.readthedocs.io/
[Ruff]: https://github.com/astral-sh/ruff
