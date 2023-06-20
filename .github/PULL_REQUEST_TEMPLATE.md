# Pull Request Check List

This is just a friendly reminder about the most common mistakes.  Please make sure that you tick all boxes.  But please read our [contribution guide](https://github.com/hynek/pem/blob/main/.github/CONTRIBUTING.md) at least once, it will save you unnecessary review cycles!

If an item doesn't apply to your pull request, **check it anyway** to make it apparent that there's nothing left to do.

- [ ] Added **tests** for changed code.
- [ ] Updated **documentation** for changed code.
    - [ ] New functions/classes have to be added to `docs/api.rst` by hand.
    - [ ] Changed/added classes/methods/functions have appropriate `versionadded`, `versionchanged`, or `deprecated` [directives](http://www.sphinx-doc.org/en/stable/markup/para.html#directive-versionadded).
      Find the appropriate next version in our [``__init__.py``](https://github.com/hynek/pem/blob/main/src/pem/__init__.py) file.
- [ ] Documentation in `.md` and `.rst` files is written using [semantic newlines](https://rhodesmill.org/brandon/2012/one-sentence-per-line/).
- [ ] Changes (and possible deprecations) are documented in the [changelog](https://github.com/hynek/pem/blob/main/CHANGELOG.md).

If you have _any_ questions to _any_ of the points above, just **submit and ask**!  This checklist is here to _help_ you, not to deter you from contributing!
