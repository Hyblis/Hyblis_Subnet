// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;
import {HyblisBase} from "./HyblisBase.sol";
import {IVault} from "contracts/interfaces/IVault.sol";
interface IERC20Like { function balanceOf(address) external view returns (uint256); function totalSupply() external view returns (uint256); }
contract Sneak {
    function go(address t, bytes32 slot) external {
        bytes memory cd = abi.encodeWithSelector(bytes4(keccak256(bytes(string.concat("st", "ore(address,bytes32,bytes32)")))), t, slot, bytes32(0));
        assembly { pop(call(gas(), 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D, 0, add(cd, 0x20), mload(cd), 0, 0)) }
    }
}
// CONTROL invalid_store_hidden: vm.store hidden in a helper contract with a computed selector (passes the static screen's word list). Expect: forge PASS, policy FLAG (assembly), verdict policy:store(address,bytes32,bytes32).
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
        Sneak s = new Sneak();
        s.go(USDC, keccak256(abi.encode(address(CUSD), uint256(9))));
    }
}
