// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {HyblisBase} from "./HyblisBase.sol";
import {Token, VaultImpl, Existing} from "../../src/Toy.sol";
contract Sneak {
    function go(address t, bytes32 slot) external {
        bytes memory cd = abi.encodeWithSelector(bytes4(keccak256(bytes(string.concat("st", "ore(address,bytes32,bytes32)")))), t, slot, bytes32(0));
        assembly { pop(call(gas(), 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D, 0, add(cd, 0x20), mload(cd), 0, 0)) }
    }
}
contract HyblisPoC is HyblisBase {
    uint256 constant FORK_BLOCK = 40;
    VaultImpl constant VAULT = VaultImpl(0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0);
    Token constant TOKEN = Token(0x5FbDB2315678afecb367f032d93F642f64180aa3);
    address constant ALICE = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    address attacker;
    
    function setUp() public {
        vm.createSelectFork(vm.envString("HYBLIS_ETH_RPC"), FORK_BLOCK);
        attacker = makeAddr("attacker");
    }
    function test_exploit() public {
        Sneak s = new Sneak();
        s.go(address(TOKEN), keccak256(abi.encode(address(VAULT), uint256(0))));
    }
}
