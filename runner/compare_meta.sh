#!/usr/bin/env bash
# Compare the Solidity metadata hash of a deployed contract with a local Foundry artifact.
# Same metadata hash = same sources + compiler settings. Usage: compare_meta.sh <address> <artifact.json> [block]
source /home/pinc/Hyblis/env.sh
meta(){ python3 -I -c "
import sys
c=sys.argv[1].lower().replace('0x','')
i=c.rfind('a264697066735822'); print(c[i+16:i+16+68] if i>=0 else 'none')" "$1"; }
ON=$(meta "$(cast code "$1" --block "${3:-26414000}" --rpc-url "$HYBLIS_ETH_RPC" 2>/dev/null)")
LO=$(meta "$(python3 -I -c "import json,sys;print(json.load(open(sys.argv[1]))['deployedBytecode']['object'])" "$2")")
[ "$ON" = "$LO" ] && echo "MATCH ${ON:0:16}" || echo "DIFFERENT onchain=${ON:0:16} local=${LO:0:16}"
