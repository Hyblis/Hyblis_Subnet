"""Run the state-layer tests: python -I -B runtests.py [unittest args]. Used by run.sh."""
import os
import sys
import unittest

RUNNER = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, RUNNER)

if __name__ == "__main__":
    names = [a for a in sys.argv[1:] if not a.startswith("-")] or ["state.tests.test_mpt", "state.tests.test_ratelimit", "state.tests.test_e2e"]
    suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    res = unittest.TextTestRunner(verbosity=2 if "-v" in sys.argv else 1, stream=sys.stdout).run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
