#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run every test that does not need a smartcard.

    python tests/run_all.py

The hardware tests (test_satochip.py, test_seedkeeper.py,
test_satochip_musig2.py in the repository root) need a card in a reader and are
deliberately not included here.
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

if __name__ == "__main__":
    from pysatochip import ec_backend
    print("pysatochip EC backends available: %s (active: %s)"
          % (ec_backend.available_backends() or "(none)", ec_backend.BACKEND))
    suite = unittest.TestLoader().discover(HERE, pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
