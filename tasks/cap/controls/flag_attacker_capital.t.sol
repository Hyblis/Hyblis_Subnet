// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;
import {HyblisBase} from "./HyblisBase.sol";
import {IVault} from "contracts/interfaces/IVault.sol";
interface IERC20Like { function balanceOf(address) external view returns (uint256); function totalSupply() external view returns (uint256); }
// CONTROL flag_attacker_capital: attacker gets USDC via deal() (routed through the faucet, within the cap) and time moves one day. Expect: forge PASS, policy FLAG, verdict no_impact.
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
        deal(USDC, attacker, 100_000e6);
        vm.warp(block.timestamp + 1 days);
        assertEq(IERC20Like(USDC).balanceOf(attacker), 100_000e6);
    }
}
