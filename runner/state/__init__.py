"""Hyblis runner state layer: verified per-program state snapshots and the read-only fork proxy.

Modules: mpt (proof + header verification), store (snapshot format), fork_proxy (runner side),
snapshot (operator side: collect, build, extend, verify), jsonrpc (framing, clients, server).
"""
