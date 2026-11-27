"""Static policy check (runner/policy_check.py): the controls still get their expected
verdicts, findings name the line as written, the stdin mode the gateway uses gives the same
result, and hostile 256 KiB inputs that used to take minutes (quadratic or worse regexes)
are checked in well under a second each.
"""
import json
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "runner"))
import policy_check as pc  # noqa: E402

TASKS = ROOT / "tasks"

# every control against its expected verdict, every template PASSes
n = 0
for task_dir in sorted(p for p in TASKS.iterdir() if (p / "controls" / "expected.json").exists()):
    manifest = json.loads((task_dir / "manifest.json").read_text())
    expected = json.loads((task_dir / "controls" / "expected.json").read_text())
    for name, want in expected.items():
        verdict, findings = pc.check(manifest, (task_dir / "controls" / name).read_text())
        assert verdict == want["policy"], (task_dir.name, name, verdict, findings)
        n += 1
    verdict, findings = pc.check(manifest, (task_dir / "poc" / "HyblisPoC.t.sol").read_text())
    assert verdict == "PASS", (task_dir.name, findings)
print(f"ok {n} controls get their expected verdict; the templates pass")

cap = json.loads((TASKS / "cap" / "manifest.json").read_text())
tpl = (TASKS / "cap" / "poc" / "HyblisPoC.t.sol").read_text()
bad = tpl.replace("vm.startPrank(attacker);", "vm.startPrank(attacker);\n        vm.store(LENDER, bytes32(0), bytes32(0));")
line = next(i for i, s in enumerate(bad.splitlines(), 1) if "vm.store(LENDER" in s)
assert pc.check(cap, bad) == ("REJECT", [{"level": "REJECT", "reason": "forbidden cheatcode vm.store", "line": line}])
# lines are lines of the file as written, even after multi-line comments the check ignores
commented = "/**\n * @notice a NatSpec block\n * over three lines\n */\n" + bad.replace("function setUp", "/* one\n two */ function setUp")
assert pc.check(cap, commented)[1][0]["line"] == line + 5, pc.check(cap, commented)
print("ok a finding names the line as written, after multi-line comments too")

# the gateway runs the check as a separate process with the PoC on stdin
for src in (tpl, bad, commented + "\r\n// crlf\r\n"):
    p = subprocess.run([sys.executable, "-I", str(ROOT / "runner" / "policy_check.py"), str(TASKS / "cap" / "manifest.json"), "-"],
                       input=src.encode(), capture_output=True, env={}, timeout=60)
    out = json.loads(p.stdout)
    verdict, findings = pc.check(cap, src)
    assert out == {"verdict": verdict, "findings": findings} and p.returncode == {"PASS": 0, "FLAG": 1, "REJECT": 2}[verdict]
print("ok stdin mode (as the gateway runs it) matches the in-process check, exit code included")

L = 256 * 1024
hostile = {
    "one long word": "a" * L,
    "unclosed /* repeated": "/*a" * (L // 3),
    "vm.prank( repeated, no ';'": "vm.prank(" * (L // 9),
    "vm.createSelectFork( repeated": "vm.createSelectFork(" * (L // 20),
    "vm.deal( repeated": "vm.deal(" * (L // 8),
    "deal( repeated": " deal(" * (L // 6),
    "hoax( repeated": "hoax(" * (L // 5),
    "address( with 256K blanks": "vm.prank(address(" + " " * (L - 40) + "x, y));",
    "x = a(a(a(...": "x = " + "a(" * ((L - 4) // 2),
    "20K findings": "vm.store(1);\n" * (L // 13),
}
worst = 0.0
for label, src in hostile.items():
    assert len(src.encode()) <= L
    t0 = time.perf_counter()
    verdict, _ = pc.check(cap, src)
    dt = time.perf_counter() - t0
    worst = max(worst, dt)
    assert verdict == "REJECT", label
    assert dt < 2.0, f"{label}: {dt:.2f}s"
print(f"ok {len(hostile)} hostile 256 KiB inputs, slowest {worst * 1000:.0f} ms")
print("ALL POLICY CHECK TESTS PASS")
