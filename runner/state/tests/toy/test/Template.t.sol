// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import "../src/Toy.sol";

// Stand-in for a program's Hyblis-owned PoC template: it is what `snapshot.py collect` runs.
// Expected values come from anvil at the pinned block (EXP_* env vars set by test_e2e.py).
contract Template is Test {
    function setUp() public {
        vm.createSelectFork(vm.envString("HYBLIS_ETH_RPC"), vm.envUint("PIN"));
    }

    function test_template() public {
        Vault v = Vault(payable(vm.envAddress("VAULT")));
        Token t = Token(vm.envAddress("TOKEN"));
        address eoa = vm.envAddress("EOA");
        assertEq(block.number, vm.envUint("PIN"), "block number");
        assertEq(block.timestamp, vm.envUint("EXP_TS"), "timestamp");
        assertEq(block.basefee, vm.envUint("EXP_BASEFEE"), "basefee");
        assertEq(block.prevrandao, vm.envUint("EXP_PREVRANDAO"), "prevrandao");
        assertEq(blockhash(block.number - 1), vm.envBytes32("EXP_BH1"), "blockhash n-1");
        assertEq(blockhash(block.number - 5), vm.envBytes32("EXP_BH5"), "blockhash n-5");
        assertEq(v.counter(), vm.envUint("EXP_COUNTER"), "counter");
        assertEq(v.data(1), vm.envUint("EXP_DATA1"), "data[1] (changed after the pinned block)");
        assertEq(v.data(1010), vm.envUint("EXP_DATA1010"), "data[1010]");
        assertEq(v.list(5), vm.envUint("EXP_LIST5"), "list[5]");
        assertEq(v.owner(), eoa, "owner");
        assertEq(address(v).balance, vm.envUint("EXP_VAULT_ETH"), "vault eth");
        assertEq(address(v).codehash, vm.envBytes32("EXP_VAULT_CODEHASH"), "vault codehash");
        assertEq(t.balanceOf(address(v)), vm.envUint("EXP_VAULT_TOK"), "vault token balance");
        assertEq(t.totalSupply(), vm.envUint("EXP_SUPPLY"), "supply");
        assertEq(eoa.balance, vm.envUint("EXP_EOA_ETH"), "eoa eth");
        assertEq(vm.getNonce(eoa), vm.envUint("EXP_EOA_NONCE"), "eoa nonce");
        assertEq(vm.envAddress("SPRAYED").balance, 1, "sprayed account");
        // what a real template does next: an attacker account, funding, time and block moves
        address attacker = makeAddr("attacker");
        vm.deal(attacker, 1 ether);
        vm.prank(attacker);
        v.set(7, 7);
        vm.roll(block.number + 3);
        vm.warp(block.timestamp + 36);
        assertEq(v.data(7), 7);
        emit log_named_uint("hyblis-toy data1", v.data(1));
    }
}
