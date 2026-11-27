// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;
import {HyblisBase} from "./HyblisBase.sol";
interface IERC20Like { function balanceOf(address) external view returns (uint256); }

// Hyblis PoC template, task aave-v4 (scaffold: the verification pass sets FORK_BLOCK and the in-scope addresses).
// Title: <one line> | Contract: <in-scope contract> | Function: <name> | Claimed severity: medium or low
//
// Rules. The runner checks each one call by call in forge's own trace; your asserts and logs are ignored.
// 1. One file, this one: contract HyblisPoC is HyblisBase, importing ./HyblisBase.sol (the runner uses its own copy).
// 2. setUp() forks exactly once, at the pinned block: vm.createSelectFork(vm.envString("HYBLIS_ETH_RPC"), FORK_BLOCK).
// 3. One test, test_exploit(). If the exploit needs separate transactions, put each one in a public
//    step1() .. stepN() (no arguments, no gaps) and call them in order from test_exploit().
// 4. Act only as accounts from makeAddr / makeAddrAndKey, contracts you deploy, or this contract. Never prank
//    a protocol contract, a trusted role, a whale or a victim. Governance and privileged roles are trusted.
// 5. Capital only through _fund(token, to, amount) (deal() is routed the same way), within the task's cap.
//    Not allowed: vm.deal, hoax, vm.store, vm.etch, vm.mockCall, ffi, files, other forks, env reads, snapshots.
// 6. A trusted-role action or an oracle move only through _asRole / _setPrice, and only what the task lists.
// 7. Time moves forward only, within the task's limits.
// 8. Profit must end in an account you control. Hyblis measures the protocol itself (balances, invariants,
//    "can a supplier still withdraw" probes) on the exploited fork and on a clean fork of the same block.
// 9. The file must also pass in plain forge test: it is the file that gets filed. Do not rely on msg.sender,
//    address(this), the test contract's ETH, gas or the RPC URL.
// Only Medium and Low findings are filed from this task at launch.
contract HyblisPoC is HyblisBase {
    // PENDING: the verification pass sets FORK_BLOCK and the in-scope addresses from live, verified sources.
    uint256 constant FORK_BLOCK = 0; // <-- set to the pinned block before release
    address attacker;

    function setUp() public {
        require(FORK_BLOCK != 0, "aave-v4 task not finalized: set FORK_BLOCK (verification pass)");
        vm.createSelectFork(vm.envString("HYBLIS_ETH_RPC"), FORK_BLOCK);
        attacker = makeAddr("attacker");
    }

    function test_exploit() public {
        vm.startPrank(attacker);
        //  ... your steps, acting only as `attacker` ...
        vm.stopPrank();
        // assert the impact you claim (read by the platform's judges, ignored by Hyblis)
    }
}
