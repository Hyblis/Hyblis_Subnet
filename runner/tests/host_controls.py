#!/usr/bin/env python3
"""Cap controls (and hostile probes) through the runner exactly as the agent runs a job on the shared host:
fresh fork proxy over the verified snapshot, isolate=True, bare numeric forge uid. Run as root.
Every control must reach its expected verdict (tasks/cap/controls/expected.json); every hostile probe must
be rejected. Usage: python runner/tests/host_controls.py [--uid 64123]"""
import json, os, sys, tempfile, time
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import run_submission as rs  # noqa: E402
from state import fork_proxy  # noqa: E402

ROOT = HERE.parents[1]
UID = sys.argv[sys.argv.index("--uid") + 1] if "--uid" in sys.argv else "64123"
manifest = json.loads((ROOT / "tasks/cap/manifest.json").read_text())["chain"]
snap = ROOT / "runner-data/snapshots/cap" / manifest["snapshot_digest"].split(":", 1)[1]
expected = json.loads((ROOT / "tasks/cap/controls/expected.json").read_text())
# runner mode: a control the static screen REJECTs never reaches forge, so its verdict is "screen"
items = [(ROOT / "tasks/cap/controls" / n, {"reproduced": False, "error": "screen"} if e["policy"] == "REJECT" else e["verdict"])
         for n, e in sorted(expected.items())]
items.append((HERE / "hostile/read_secret_hidden.t.sol", {"reproduced": False, "error": "policy:readFile(string)"}))
opts = rs.Options(sandbox="netns", forge_user=UID, isolate=True, max_memory_gb=8,
                  jobs_dir=str(ROOT / "run/runner-jobs"), foundry_bin=str(ROOT / "tools/foundry/bin"),
                  svm_dir=str(ROOT / ".home/.svm"))
fails = 0
for path, want in items:
    sock = str(ROOT / "run/runner-sockets" / f"ctl-{os.getpid()}-{int(time.time() * 1000)}.ipc")
    h = fork_proxy.serve(str(snap), sock, socket_mode=0o666, expect_digest=manifest["snapshot_digest"],
                         expect_block_hash=manifest["fork_block_hash"], expect_chain_id=int(manifest["chain_id"]))
    t0 = time.time()
    try:
        v = rs.reproduce("cap", path.read_text(), ROOT / "runner-data/projects/cap", "ctl", fork_url=sock, fork=h, options=opts)
    finally:
        h.close()
    ok = v.get("reproduced") == want["reproduced"] and (v.get("error") == want.get("error") or
                                                         (path.parent.name == "hostile" and not v.get("reproduced")))
    fails += 0 if ok else 1
    print(f"{'ok  ' if ok else 'FAIL'} {path.name:34s} {v.get('error') or v.get('impact_type')!s:42s} "
          f"(expected {want.get('error')}) {time.time() - t0:.1f}s", flush=True)
print("\nALL HOST CONTROLS MATCH" if not fails else f"\n{fails} HOST CONTROLS FAILED")
sys.exit(1 if fails else 0)
