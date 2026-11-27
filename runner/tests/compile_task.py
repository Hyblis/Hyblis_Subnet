#!/usr/bin/env python3
"""Compile a task's PoC template and controls together with the runner files, the way a job does
(hard-linked copy of the prepared project, hardened foundry.toml, generated HyblisSpec.sol), without
running anything and without a fork. Catches incompatibilities with the task's forge-std / solc before a
release. The prepared project is never modified.
Usage: compile_task.py <task_id> [--project <prepared project>]   (run as pinc; idle priority)
"""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUNNER = HERE.parent
ROOT = RUNNER.parent
sys.path.insert(0, str(RUNNER))
import gen_spec  # noqa: E402
import run_submission as rs  # noqa: E402
import sanitize_foundry_toml as sft  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("task")
    ap.add_argument("--project")
    a = ap.parse_args()
    tdir = ROOT / "tasks" / a.task
    manifest = json.loads((tdir / "manifest.json").read_text())
    project = Path(a.project) if a.project else ROOT / manifest["code"]["upstream_checkout"]
    spec = gen_spec.compile_spec(json.loads((tdir / "impact-spec.json").read_text()), allow_draft=True)
    work = Path(tempfile.mkdtemp(prefix=f"hyblis-compile-{a.task}-"))
    try:
        proj = work / "project"
        proj.mkdir()
        rs._copy_project(project, proj, "test/hyblis")
        pd = proj / "test" / "hyblis"
        pd.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(tdir / "poc" / "HyblisPoC.t.sol", pd / "HyblisPoC.t.sol")
        for name in rs.RUNNER_FILES:
            shutil.copyfile(rs.SOL / name, pd / name)
        if (tdir / "poc" / "HyblisBase.sol").read_bytes() != (rs.SOL / "HyblisBase.sol").read_bytes():
            sys.exit(f"tasks/{a.task}/poc/HyblisBase.sol differs from runner/sol/HyblisBase.sol")
        (pd / "HyblisSpec.sol").write_text(gen_spec.render_solidity(spec))
        controls = sorted((tdir / "controls").glob("*.t.sol")) if (tdir / "controls").exists() else []
        for c in controls:
            shutil.copyfile(c, pd / f"Control_{c.name}")
        cfg = tomllib.loads((project / "foundry.toml").read_text())
        (proj / "foundry.toml").write_text(sft.runner_toml(cfg, rs._solc_path(cfg, rs.DEFAULT_SVM)))
        env = {"PATH": f"{rs._default_foundry_bin()}:/usr/bin:/bin", "HOME": str(work), "NO_COLOR": "1"}
        p = subprocess.run(["chrt", "--idle", "0", "nice", "-n", "19", "forge", "build", "--offline"], cwd=proj,
                           env=env, capture_output=True, text=True, timeout=3600)
        if p.returncode != 0:
            print((p.stdout + p.stderr)[-4000:])
            sys.exit(f"{a.task}: compile FAILED")
        steps = rs._abi_shape(proj, spec["limits"]["max_steps"])
        print(f"{a.task}: template, {len(controls)} controls and the runner files compile "
              f"(forge-std from the task project); template steps = {steps}")
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
