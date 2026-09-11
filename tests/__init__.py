# Makes `python -m unittest discover -s tests` work from the repository root.
# The test modules also insert this directory on sys.path so they can be run
# directly as scripts (python tests/test_ec_math.py).
