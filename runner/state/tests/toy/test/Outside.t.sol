// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import "../src/Toy.sol";

// Reads state the template never touched: fails with a snapshot miss until the snapshot is extended.
contract OutsideRead is Test {
    function setUp() public {
        vm.createSelectFork(vm.envString("HYBLIS_ETH_RPC"), vm.envUint("PIN"));
    }

    function test_outside() public {
        Outside o = Outside(vm.envAddress("OUTSIDE"));
        assertEq(o.secret(), vm.envUint("EXP_SECRET"), "secret");
        assertEq(o.credit(vm.envAddress("EOA")), vm.envUint("EXP_CREDIT"), "credit");
        assertEq(Token(vm.envAddress("TOKEN")).balanceOf(address(0xBEEF)), vm.envUint("EXP_BEEF_TOK"), "beef tok");
        assertEq(vm.envAddress("FRESH").balance, 0, "fresh account");
        // a miss is not catchable: the EVM stops with a database error, so this try never "succeeds"
        try this.peek() returns (uint256 x) {
            assertEq(x, vm.envUint("EXP_PEEK"), "peek");
        } catch {
            revert("unreachable: misses are not catchable");
        }
    }

    function peek() external view returns (uint256) {
        return Vault(payable(vm.envAddress("VAULT"))).data(424242);
    }
}

// Things the proxy must refuse (and record as refusals, not misses).
contract Escape is Test {
    function setUp() public {
        vm.createSelectFork(vm.envString("HYBLIS_ETH_RPC"), vm.envUint("PIN"));
    }

    function test_write_method() public {
        vm.rpc("anvil_setBalance", '["0x000000000000000000000000000000000000bEEF","0x1"]');
    }

    function test_other_block() public {
        vm.createSelectFork(vm.envString("HYBLIS_ETH_RPC"), vm.envUint("PIN") - 2);
        emit log_named_uint("bal", vm.envAddress("EOA").balance);
    }

    function test_latest_fork() public {
        vm.createSelectFork(vm.envString("HYBLIS_ETH_RPC"));
    }
}
