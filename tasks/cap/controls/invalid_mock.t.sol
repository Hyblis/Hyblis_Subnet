// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;
import {HyblisBase} from "./HyblisBase.sol";
import {IVault} from "contracts/interfaces/IVault.sol";
interface IERC20Like { function balanceOf(address) external view returns (uint256); function totalSupply() external view returns (uint256); }
// CONTROL invalid_mock: mocks the Oracle price. Expect: policy REJECT, verdict policy:mockCall(address,bytes,bytes).
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
    address constant ORACLE = 0xcD7f45566bc0E7303fB92A93969BB4D3f6e662bb;
    function test_exploit() public {
        vm.mockCall(ORACLE, abi.encodeWithSignature("getPrice(address)", USDC), abi.encode(uint256(1), uint256(0)));
        assertTrue(true);
    }
}
