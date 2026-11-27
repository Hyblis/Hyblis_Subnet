// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;
import {HyblisBase} from "./HyblisBase.sol";
interface IERC20Like { function balanceOf(address) external view returns (uint256); }

// Hyblis PoC template, task aave-v4: Aave V4 on Ethereum, verified at block 26508006 (tag v0.5.11; every in-scope
// contract's live code is a Sourcify full match of the tag). The full scope is tasks/aave-v4/impact-spec.json in_scope.
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
//    This task lists none: Aave V4 needs no keeper between steps, and its price sources are out of scope.
// 7. Time moves forward only, within the task's limits.
// 8. Profit must end in an account you control. Hyblis measures the protocol itself (balances, invariants,
//    "can a supplier still withdraw" probes) on the exploited fork and on a clean fork of the same block.
// 9. The file must also pass in plain forge test: it is the file that gets filed. Do not rely on msg.sender,
//    address(this), the test contract's ETH, gas or the RPC URL.
// Only Medium and Low findings are filed from this task at launch.
contract HyblisPoC is HyblisBase {
    uint256 constant FORK_BLOCK = 26508006;
    // Hubs (custody of every supplied asset)
    address constant HUB_CORE = 0xCca852Bc40e560adC3b1Cc58CA5b55638ce826c9;
    address constant HUB_PLUS = 0x06002e9c4412CB7814a791eA3666D905871E536A;
    address constant HUB_PRIME = 0x943827DCA022D0F354a8a8c332dA1e5Eb9f9F931;
    address constant HUB_GLOBAL_DOLLAR = 0x62d63197660c080236193CA60b70E49A08E90368;
    // Lending spokes (users supply, borrow, repay, withdraw and liquidate here); the main one:
    address constant MAIN_SPOKE = 0x94e7A5dCbE816e498b89aB752661904E2F56c485;
    address constant TREASURY_SPOKE = 0xB9B0b8616f6Bf6841972a52058132BE08d723155;
    // Capital tokens (fund with _fund, within the task's cap)
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant WBTC = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;
    address attacker;

    function setUp() public {
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
