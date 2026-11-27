// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import "forge-std/Script.sol";
import {Token, VaultImpl, Proxy, Existing, TxGuardVault, Feed, Lender} from "../src/Toy.sol";

/// Deploys the toy protocol on a LOCAL anvil chain with anvil's public test keys. The addresses are
/// deterministic (deployer nonce order); runner/tests/toy_chain.py checks them against toy-addresses.json.
contract Deploy is Script {
    uint256 constant K0 = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80; // deployer / owner
    uint256 constant K1 = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d; // alice
    uint256 constant K2 = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a; // bob
    uint256 constant K3 = 0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6; // keeper
    uint256 constant K4 = 0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a; // carol (borrower)
    uint256 constant K5 = 0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba; // dave (guard vault)

    function run() external {
        address deployer = vm.addr(K0);
        address alice = vm.addr(K1); address bob = vm.addr(K2); address keeper = vm.addr(K3);
        address carol = vm.addr(K4); address dave = vm.addr(K5);
        vm.startBroadcast(K0);
        Token t = new Token();
        VaultImpl impl = new VaultImpl();
        Proxy p = new Proxy(address(impl));
        VaultImpl(address(p)).initialize(t, address(0xFEE5), keeper, deployer);
        Existing e = new Existing();
        TxGuardVault g = new TxGuardVault(t);
        Feed f = new Feed(3000e8);
        Lender l = new Lender(t, f);
        t.mint(alice, 100e18); t.mint(bob, 100e18); t.mint(dave, 1000e18);
        t.mint(address(g), 500e18);                 // other users' funds already in the guarded vault
        t.mint(address(l), 100_000e18);             // lending liquidity
        vm.stopBroadcast();
        vm.startBroadcast(K1); VaultImpl(address(p)).deposit(50e18); vm.stopBroadcast();
        vm.startBroadcast(K2); VaultImpl(address(p)).deposit(30e18); vm.stopBroadcast();
        vm.startBroadcast(K5); g.deposit(1000e18); vm.stopBroadcast();
        vm.startBroadcast(K4); l.depositCollateral{value: 10 ether}(); l.borrow(22_000e18); vm.stopBroadcast();
        console.log("ADDR TOKEN", address(t));
        console.log("ADDR VAULT", address(p));
        console.log("ADDR VAULT_IMPL", address(impl));
        console.log("ADDR EXISTING", address(e));
        console.log("ADDR GUARD", address(g));
        console.log("ADDR FEED", address(f));
        console.log("ADDR LENDER", address(l));
        console.log("ADDR DEPLOYER", deployer);
        console.log("ADDR ALICE", alice);
        console.log("ADDR BOB", bob);
        console.log("ADDR KEEPER", keeper);
        console.log("ADDR CAROL", carol);
        console.log("ADDR DAVE", dave);
    }
}
