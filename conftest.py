collect_ignore = []

try:
    import twisted.internet.ssl  # noqa
except ImportError:
    collect_ignore.append("tests/test_twisted.py")
