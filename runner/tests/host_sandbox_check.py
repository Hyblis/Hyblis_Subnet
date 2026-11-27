#!/usr/bin/env python3
"""Shared-host sandbox check (run as root on the platform host, before any outside proof runs there).

Runs probes as the forge user inside exactly the sandbox a job gets (run_submission.sandbox_prefix with
isolate=True, a bare numeric uid, the job's bind list) and checks that the proof sees nothing of the host:
no /home contents but its own paths, no keys, no other projects, no /root, no other processes, no network, read-only
tools, a writable job directory, working forge. Then checks the host saw no mount change.
Usage: python runner/tests/host_sandbox_check.py [--uid 64123]
"""
import os, shutil, socket, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import run_submission as rs  # noqa: E402

ROOT = HERE.parents[1]
UID = sys.argv[sys.argv.index("--uid") + 1] if "--uid" in sys.argv else "64123"
FAILS = []


def check(ok, msg):
    print(("ok   " if ok else "FAIL ") + msg, flush=True)
    if not ok:
        FAILS.append(msg)


def main():
    if os.geteuid() != 0:
        sys.exit("run as root")
    opts = rs.Options(sandbox="netns", forge_user=UID, isolate=True, max_memory_gb=8,
                      jobs_dir=str(ROOT / "run" / "runner-jobs"), foundry_bin=str(ROOT / "tools" / "foundry" / "bin"),
                      svm_dir=str(ROOT / ".home" / ".svm"))
    job = Path(tempfile.mkdtemp(prefix="hyblis-sbx-", dir=opts.jobs_dir))
    sockdir = ROOT / "run" / "runner-sockets"
    sock = sockdir / f"probe-{os.getpid()}.ipc"
    srv = socket.socket(socket.AF_UNIX); srv.bind(str(sock)); os.chmod(sock, 0o666); srv.listen(1)
    mounts_before = Path("/proc/self/mountinfo").read_text()
    try:
        rs._chown_tree(job, UID)
        binds = [(job, False), (opts.foundry_bin, True), (opts.svm_dir, True), (sockdir, False)]
        pre = rs.sandbox_prefix(opts, binds) + rs.limits_prefix(opts, 10 * 1024 * 1024)

        def sh(script, timeout=60):
            p = subprocess.run([*pre, "/bin/sh", "-c", script], capture_output=True, text=True, timeout=timeout,
                               env={"PATH": "/usr/bin:/bin", "HOME": str(job)})
            return p.returncode, (p.stdout + p.stderr).strip()

        rc, out = sh("id -u"); check(out == UID, f"runs as uid {UID} (got {out!r})")
        rc, out = sh("ls -A /home; ls -A /home/pinc; ls -A /home/pinc/Hyblis")
        check(set(out.split()) <= {"pinc", "Hyblis", "run", "tools", ".home"}, f"/home shows only the job's own paths: {out.split()}")
        for secret in ("/home/pinc/Hyblis/run/cloudflare.env", "/home/pinc/Hyblis/run/tunnel.token",
                       "/home/pinc/Hyblis/.home/.bittensor/wallets/hyblis-sn/coldkey", "/home/pinc/Hyblis/platform/data/hyblis.db",
                       "/root/.claude", "/etc/shadow"):
            rc, out = sh(f"head -c 1 {secret} >/dev/null 2>&1 && echo READ || echo denied")
            check(out == "denied", f"cannot read {secret}")
        rc, out = sh("ls -A /root 2>&1"); check(out == "" or "Permission denied" in out, f"/root shows nothing ({out[:60]!r})")
        rc, out = sh("ls /proc | grep -c '^[0-9]'"); check(int(out or 99) <= 6, f"sees only its own processes ({out})")
        rc, out = sh("python3 -c \"import socket; s=socket.socket(); s.settimeout(3); s.connect(('1.1.1.1', 443))\" 2>&1 && echo CONNECTED || echo blocked")
        check(out.endswith("blocked"), "no network")
        rc, out = sh(f"touch {opts.foundry_bin}/x 2>&1 && echo WROTE || echo ro")
        check(out.endswith("ro"), "forge directory is read-only")
        rc, out = sh(f"touch {job}/x && echo ok"); check(out == "ok", "job directory is writable")
        rc, out = sh(f"python3 -c \"import socket; s=socket.socket(socket.AF_UNIX); s.connect('{sock}'); print('ok')\"")
        check(out == "ok", "can reach its fork socket")
        rc, out = sh(f"{opts.foundry_bin}/forge --version | head -1"); check(out.startswith("forge Version"), f"forge runs ({out[:40]})")
        rc, out = sh("grep -E 'Max processes|Max address space' /proc/self/limits")
        lim = {l.split("  ")[0]: l.split()[-3] for l in out.splitlines()}
        check(lim.get("Max processes") == "512" and lim.get("Max address space") == str(8 * 1024 ** 3), f"process and memory caps set ({lim})")
        rc, out = sh("for i in $(seq 1 600); do sleep 5 & done 2>&1 | tail -1; echo done")
        check("Resource temporarily unavailable" in out or "fork" in out.lower(), "process cap stops a fork flood")
    finally:
        srv.close(); sock.unlink(missing_ok=True); shutil.rmtree(job, ignore_errors=True)
    check(Path("/proc/self/mountinfo").read_text() == mounts_before, "the host saw no mount change")
    check(len(os.listdir("/home/pinc")) > 1 and Path("/home/pinc/Hyblis/run/cloudflare.env").exists(), "host /home intact")
    print("\nSANDBOX CHECK PASSED" if not FAILS else f"\n{len(FAILS)} SANDBOX CHECKS FAILED")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
