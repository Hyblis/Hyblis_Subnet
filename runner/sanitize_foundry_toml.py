#!/usr/bin/env python3
"""Write a Hyblis-controlled copy of a repo's foundry.toml for PoC runs.

Two modes.

Default (local control runs, runner/local_controls.sh): every profile keeps its settings, but
  ffi = false, fs_permissions = [] (no file reads/writes from tests), the trace design's hardened keys
  (below) are forced, and the rpc_endpoints / etherscan sections are dropped (the PoC gets its fork URL
  only from HYBLIS_ETH_RPC).

--runner (the isolated runner, runner/run_submission.py): only the default profile is written, and only
  its compile settings are copied (an allowlist: sources, remappings, compiler and optimizer). Every
  runtime setting comes from Hyblis: the hardened keys below, the solc binary given with --solc, the
  harness gas budget given with --gas-limit (gen_spec.harness_gas_limit: (2 + max_steps) x poc_gas plus
  the measurement reserve), and the linter off. Keys such as eth_rpc_url, sender, tx_origin,
  initial_balance, block_* or libraries can therefore never reach a run.

Hardened keys (design section 5.3):
  ffi = false, fs_permissions = [], offline = true, dynamic_test_linking = false, isolate = true,
  gas_limit = 4000000000 (runner mode: the task's harness budget), memory_limit = 536870912,
  always_use_create_2_factory = false

Usage: sanitize_foundry_toml.py [--runner --solc <path> [--gas-limit <gas>]] <repo foundry.toml | /dev/null> <output .toml>
Run forge with --config-path <output .toml> (output in the same directory), or write it as foundry.toml.
"""
import argparse
import sys
import tomllib

DROP = {"rpc_endpoints", "etherscan"}
HARDENED = {
    "ffi": False,
    "fs_permissions": [],
    "offline": True,
    "dynamic_test_linking": False,
    "isolate": True,
    "gas_limit": 4_000_000_000,
    "memory_limit": 536_870_912,
    "always_use_create_2_factory": False,
}
# runner mode: the only keys copied from the task project's default profile
COMPILE_KEYS = {
    "src", "test", "script", "out", "libs", "remappings", "auto_detect_remappings", "solc_version", "solc",
    "evm_version", "optimizer", "optimizer_runs", "optimizer_details", "via_ir", "use_literal_content",
    "bytecode_hash", "cbor_metadata", "ignored_error_codes", "ignored_warnings_from", "include_paths",
    "model_checker", "compilation_restrictions", "additional_compiler_profiles", "revert_strings",
    "sparse_mode", "allow_paths", "extra_output", "extra_output_files", "build_info", "unchecked_cheatcode_artifacts",
}
RUNNER_DROP_COMPILE = {"solc", "solc_version", "allow_paths", "extra_output", "extra_output_files", "build_info",
                       "include_paths", "unchecked_cheatcode_artifacts"}


def clean(profile):
    out = {}
    for k, v in profile.items():
        if k in DROP:
            continue
        out[k] = v
    out.update(HARDENED)
    return out


def fmt(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(v, list):
        return "[" + ", ".join(fmt(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{ " + ", ".join(f'{k} = {fmt(x)}' for k, x in v.items()) + " }"
    raise TypeError(type(v))


def emit(table, path, lines):
    scalars = {k: v for k, v in table.items() if not isinstance(v, dict)}
    subs = {k: v for k, v in table.items() if isinstance(v, dict)}
    if path:
        lines.append(f"[{'.'.join(path)}]")
    for k, v in scalars.items():
        lines.append(f"{k} = {fmt(v)}")
    lines.append("")
    for k, v in subs.items():
        emit(v, path + [k], lines)


def solc_version(cfg: dict) -> str | None:
    """The solc version the project pins (default profile), if any."""
    prof = cfg.get("profile", {}).get("default", {})
    v = prof.get("solc_version") or prof.get("solc")
    return str(v) if v and all(c.isdigit() or c == "." for c in str(v)) else None


POC_TEST_DIR = "test"                # parent of the runner's test/hyblis/
MAX_OPTIMIZER_RUNS = 2 ** 32 - 1     # Foundry 1.9.0 refuses a larger optimizer_runs (solc reads it as u32)


def clamp_runs(v):
    """optimizer_runs above Foundry's u32 maximum (a project's "maximum runs" idiom, e.g. 444444444444)
    becomes the maximum, in the profile and in every compiler profile or restriction that sets it. It only
    affects how the job compiles the PoC: fork state is the live, deployed code."""
    if isinstance(v, dict):
        return {k: (min(x, MAX_OPTIMIZER_RUNS) if k == "optimizer_runs" and isinstance(x, int) else clamp_runs(x))
                for k, x in v.items()}
    if isinstance(v, list):
        return [clamp_runs(x) for x in v]
    return v


def runner_toml(cfg: dict, solc_path: str, gas_limit: int | None = None) -> str:
    """gas_limit: the harness test's total budget (gen_spec.harness_gas_limit of the task's spec); every
    runner job passes it. Without it (compile-only uses) the hardened default stays."""
    prof = cfg.get("profile", {}).get("default", {})
    out = clamp_runs({k: v for k, v in prof.items() if k in COMPILE_KEYS and k not in RUNNER_DROP_COMPILE})
    out["solc"] = solc_path
    # the runner writes the PoC and its own files under test/hyblis/: forge must compile that directory,
    # whatever test directory the project names for its own suite (e.g. Aave V4's "tests")
    out["test"] = POC_TEST_DIR
    out.update(HARDENED)
    if gas_limit is not None:
        if not isinstance(gas_limit, int) or isinstance(gas_limit, bool) or not 0 < gas_limit < 2 ** 63:
            raise ValueError("gas_limit must be a positive 64-bit integer")
        out["gas_limit"] = gas_limit
    lines = ["# Generated by Hyblis runner/sanitize_foundry_toml.py --runner - do not edit", ""]
    emit({"profile": {"default": out}, "lint": {"lint_on_build": False}}, [], lines)
    return "\n".join(lines)


def default_toml(cfg: dict) -> str:
    profiles = cfg.get("profile", {"default": {}})
    if "default" not in profiles:
        profiles["default"] = {}
    cfg["profile"] = {name: clean(p) for name, p in profiles.items()}
    for k in DROP:
        cfg.pop(k, None)
    lines = ["# Generated by Hyblis runner/sanitize_foundry_toml.py - do not edit", ""]
    emit(cfg, [], lines)
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runner", action="store_true")
    ap.add_argument("--solc")
    ap.add_argument("--gas-limit", type=int)
    ap.add_argument("src")
    ap.add_argument("dst")
    a = ap.parse_args()
    cfg = tomllib.load(open(a.src, "rb"))
    if a.runner:
        if not a.solc:
            sys.exit("--runner needs --solc <path to the solc binary>")
        text = runner_toml(cfg, a.solc, a.gas_limit)
    else:
        text = default_toml(cfg)
    open(a.dst, "w").write(text)


if __name__ == "__main__":
    main()
