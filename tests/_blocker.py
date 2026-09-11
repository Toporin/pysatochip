# -*- coding: utf-8 -*-
"""Make selected top-level packages unimportable.

Used by test_backend_scenarios.py to simulate environments where a dependency
is absent -- notably seedsigner-os, which ships embit and pycryptodomex but
neither cryptography nor pyOpenSSL.
"""

import sys


class _Blocker:
    def __init__(self, names):
        self.names = set(names)

    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in self.names:
            raise ModuleNotFoundError(
                "No module named %r (blocked for testing)" % fullname,
                name=fullname)
        return None


def block(*names):
    for mod in list(sys.modules):
        if mod.split('.')[0] in names:
            del sys.modules[mod]
    sys.meta_path.insert(0, _Blocker(names))
