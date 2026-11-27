// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;
import {HyblisBase} from "./HyblisBase.sol";
import {IVault} from "contracts/interfaces/IVault.sol";
interface IERC20Like { function balanceOf(address) external view returns (uint256); function approve(address, uint256) external returns (bool); }

// Hyblis PoC template, task cap. Live code = Sourcify-verified sources in tasks/cap/live-sources/.
// Title: <one line> | Contract: <in-scope contract> | Function: <name> | Claimed severity: medium
//
// Rules. The runner checks each one call by call in forge's own trace; your asserts and logs are ignored.
// 1. One file, this one: contract HyblisPoC is HyblisBase, importing ./HyblisBase.sol (the runner uses its own copy).
// 2. setUp() forks exactly once, at the pinned block: vm.createSelectFork(vm.envString("HYBLIS_ETH_RPC"), FORK_BLOCK).
// 3. One test, test_exploit(). If the exploit needs separate transactions, put each one in a public
//    step1() .. stepN() (no arguments, no gaps) and call them in order from test_exploit().
// 4. Act only as accounts from makeAddr / makeAddrAndKey, contracts you deploy, or this contract. Never prank
//    a protocol contract, a trusted role, a whale or a victim. Protocol admins are trusted.
// 5. Capital only through _fund(token, to, amount) (deal() is routed the same way), within the task's cap.
//    Not allowed: vm.deal, hoax, vm.store, vm.etch, vm.mockCall, ffi, files, other forks, env reads, snapshots.
// 6. A trusted-role action or an oracle move only through _asRole / _setPrice, and only what the task lists.
// 7. Time moves forward only, within the task's limits.
// 8. Profit must end in an account you control. Hyblis measures the protocol itself (balances, invariants,
//    "can a holder still redeem" probes) on the exploited fork and on a clean fork of the same block.
// 9. The file must also pass in plain forge test: it is the file that gets filed. Do not rely on msg.sender,
//    address(this), the test contract's ETH, gas or the RPC URL.
// Check before submitting: python runner/check.py --task cap --poc <this file> --project <cap project> --rpc <your RPC>
contract HyblisPoC is HyblisBase {
    uint256 constant FORK_BLOCK = 26429948;
    IVault constant CUSD = IVault(0xcCcc62962d17b8914c62D74FfB843d73B2a3cccC);   // cUSD (CapToken = Vault + Minter + FractionalReserve)
    address constant LENDER = 0x15622c3dbbc5614E6DFa9446603c1779647f01FC;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address attacker;

    function setUp() public {
        vm.createSelectFork(vm.envString("HYBLIS_ETH_RPC"), FORK_BLOCK);
        attacker = makeAddr("attacker");
    }

    function test_exploit() public {
        // _fund(USDC, attacker, 1_000_000e6);               // capital, if you need it
        vm.startPrank(attacker);
        // ... your attack steps here ...
        vm.stopPrank();
        // assert the impact you claim (read by the platform's judges, ignored by Hyblis)
    }
}
