"""Hyblis platform: miner gateway, finding ledger, settlement and public site.

All services stay inside the repository folder, bind to 127.0.0.1 on the reserved
9850-9869 block, and run as an unprivileged user. This package never executes a
miner's PoC; reproduction happens in the runner (runner/agent.py), inside an
isolated sandbox.
"""

__version__ = "0.1.0"
