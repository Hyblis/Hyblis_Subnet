// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;
import {HyblisBase} from "./HyblisBase.sol";
import {IVault} from "contracts/interfaces/IVault.sol";
interface IERC20Like { function balanceOf(address) external view returns (uint256); function totalSupply() external view returns (uint256); }
// CONTROL invalid_prank_protocol: impersonates the Lender to borrow vault USDC to the attacker. Expect: forge PASS, policy REJECT, verdict impersonation.
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
        vm.prank(LENDER);
        CUSD.borrow(USDC, 1_000_000e6, attacker);
        assertEq(IERC20Like(USDC).balanceOf(attacker), 1_000_000e6, "fake theft");
    }
}
