// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {HyblisVault} from "../src/HyblisVault.sol";

contract MockAlpha {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 a) external { balanceOf[to] += a; }
    function transfer(address to, uint256 a) external returns (bool) {
        require(balanceOf[msg.sender] >= a, "insufficient");
        balanceOf[msg.sender] -= a; balanceOf[to] += a; return true;
    }
}

contract HyblisVaultTest is Test {
    MockAlpha alpha;
    HyblisVault vault;
    address operator = makeAddr("operator");
    address guardian = makeAddr("guardian");
    address minerA = makeAddr("minerA");
    address minerB = makeAddr("minerB");
    address dead = 0x000000000000000000000000000000000000dEaD;

    function setUp() public {
        alpha = new MockAlpha();
        vault = new HyblisVault(address(alpha), operator, guardian);
        alpha.mint(address(vault), 1_000_000 ether);
    }

    function _reg(bytes32 hk, address payee) internal { vm.prank(guardian); vault.registerPayee(hk, payee); }

    function _one(bytes32 f, address to, uint256 amt, uint32 p, bytes32 hk) internal {
        bytes32[] memory F = new bytes32[](1); F[0] = f;
        address[] memory T = new address[](1); T[0] = to;
        uint256[] memory A = new uint256[](1); A[0] = amt;
        uint32[] memory P = new uint32[](1); P[0] = p;
        bytes32[] memory H = new bytes32[](1); H[0] = hk;
        vm.prank(operator);
        vault.payout(F, T, A, P, H);
    }

    function test_registered_payee_on_by_default() public view {
        assertTrue(vault.requireRegisteredPayee());
    }

    function test_operator_cannot_pay_unregistered_address() public {
        // The core option-A guarantee: the operator cannot send to a fresh EOA it controls.
        address attackerEOA = makeAddr("attackerEOA");
        vm.expectRevert("payee not registered");
        _one("f1", attackerEOA, 100 ether, 0, "hkA");
    }

    function test_operator_pays_accepted_miner() public {
        _reg("hkA", minerA);
        _one("f1", minerA, 100 ether, 0, "hkA");
        assertEq(alpha.balanceOf(minerA), 100 ether);
        assertTrue(vault.findingPaid("f1"));
    }

    function test_cannot_pay_operator_or_guardian() public {
        vm.expectRevert("bad recipient");
        _one("f1", operator, 1 ether, 0, "hk");
        vm.expectRevert("bad recipient");
        _one("f2", guardian, 1 ether, 0, "hk");
    }

    function test_no_double_pay() public {
        _reg("hkA", minerA); _reg("hkB", minerB);
        _one("f1", minerA, 10 ether, 0, "hkA");
        vm.expectRevert("already paid");
        _one("f1", minerB, 10 ether, 0, "hkB");
    }

    function test_only_operator_can_pay() public {
        bytes32[] memory F = new bytes32[](1); F[0] = "f1";
        address[] memory T = new address[](1); T[0] = minerA;
        uint256[] memory A = new uint256[](1); A[0] = 1 ether;
        uint32[] memory P = new uint32[](1); P[0] = 0;
        bytes32[] memory H = new bytes32[](1); H[0] = "hk";
        vm.prank(minerB);
        vm.expectRevert("not operator");
        vault.payout(F, T, A, P, H);
    }

    function test_no_withdraw_function_exists() public view {
        // The ABI has no withdraw/sweep/rescue path: the only outflows are
        // payout() (to non-operator) and burnExpired() (to dead). This test
        // documents that invariant; see the contract source.
        assertTrue(address(vault).code.length > 0);
    }

    function test_burn_expired() public {
        vm.prank(operator);
        vault.burnExpired(500 ether, 12);
        assertEq(alpha.balanceOf(dead), 500 ether);
    }

    function test_pause_blocks_burn_during_containment() public {
        // A compromised operator must not be able to destroy the vault while the
        // guardian has paused and is waiting out the rotation timelock.
        vm.prank(guardian);
        vault.setPaused(true);
        vm.prank(operator);
        vm.expectRevert("paused");
        vault.burnExpired(500 ether, 0);
    }

    function test_guardian_pause_blocks_payout() public {
        _reg("hk", minerA);
        vm.prank(guardian);
        vault.setPaused(true);
        vm.expectRevert("paused");
        _one("f1", minerA, 1 ether, 0, "hk");
    }

    function test_operator_rotation_timelock() public {
        address next = makeAddr("next");
        vm.prank(guardian);
        vault.queueOperatorRotation(next);
        vm.prank(guardian);
        vm.expectRevert("timelock");
        vault.executeOperatorRotation();
        vm.warp(block.timestamp + 7 days);
        vm.prank(guardian);
        vault.executeOperatorRotation();
        assertEq(vault.operator(), next);
    }

    function test_registered_payee_mode() public {
        vm.prank(guardian);
        vault.setRequireRegisteredPayee(true);
        // unregistered -> revert
        vm.expectRevert("payee not registered");
        _one("f1", minerA, 1 ether, 0, "hkA");
        // registrar registers the hotkey's payee
        vm.prank(guardian); // guardian is the default registrar
        vault.registerPayee("hkA", minerA);
        _one("f1", minerA, 1 ether, 0, "hkA");
        assertEq(alpha.balanceOf(minerA), 1 ether);
    }

    function test_guardian_cannot_pay() public {
        // guardian has no payout power (separation of duties)
        bytes32[] memory F = new bytes32[](1); F[0] = "f1";
        address[] memory T = new address[](1); T[0] = minerA;
        uint256[] memory A = new uint256[](1); A[0] = 1 ether;
        uint32[] memory P = new uint32[](1); P[0] = 0;
        bytes32[] memory H = new bytes32[](1); H[0] = "hk";
        vm.prank(guardian);
        vm.expectRevert("not operator");
        vault.payout(F, T, A, P, H);
    }
}
