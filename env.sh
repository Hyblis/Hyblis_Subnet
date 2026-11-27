# Hyblis environment. Load it with: source env.sh (from the repository root)
# Keeps every tool, cache, wallet and config inside the repository so nothing is shared with
# other projects on the same host, or with the user's own ~/.bittensor, ~/.cache and other dot-folders.
export HYBLIS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export HOME="$HYBLIS_ROOT/.home"                 # SDK/btcli write ~/.bittensor here, not into pinc's real home
export PIP_CACHE_DIR="$HYBLIS_ROOT/.cache/pip"
export XDG_CACHE_HOME="$HYBLIS_ROOT/.cache"
export FOUNDRY_DIR="$HYBLIS_ROOT/tools/foundry"
export PATH="$HYBLIS_ROOT/.venv/bin:$FOUNDRY_DIR/bin:$PATH"
export BT_WALLET_PATH="$HYBLIS_ROOT/.home/.bittensor/wallets"   # Hyblis wallets only (test keys; never the owner coldkey)

export npm_config_cache="$HYBLIS_ROOT/.cache/npm"   # npm/yarn caches stay inside Hyblis
export COREPACK_HOME="$HYBLIS_ROOT/.cache/corepack"

# Hyblis Python packages (platform services, scoring engine) importable as modules.
export PYTHONPATH="$HYBLIS_ROOT/platform:$HYBLIS_ROOT/scoring:${PYTHONPATH:-}"

# Ethereum mainnet RPC for local forks (read-only state queries; never used to send transactions).
# Public archive-capable endpoints checked 2026-11-14: eth.drpc.org, 1rpc.io/eth.
export HYBLIS_ETH_RPC="${HYBLIS_ETH_RPC:-https://eth.drpc.org}"
export HYBLIS_ETH_RPC_FALLBACK="${HYBLIS_ETH_RPC_FALLBACK:-https://1rpc.io/eth}"

# PoC safety: Foundry ffi (shell commands from tests) is always OFF for Hyblis runs, whatever a repo's foundry.toml says.
export FOUNDRY_FFI=false

# Reserved port block for Hyblis services: 9850-9869, bound to 127.0.0.1 only. See docs/ports.md.
export HYBLIS_PORT_BASE=9850
