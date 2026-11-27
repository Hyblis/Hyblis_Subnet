// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;
import {HyblisBase} from "./HyblisBase.sol";
// HOSTILE probe: tries to read the platform's Cloudflare key through vm.readFile, hidden in a helper with a
// computed selector (passes the static screen's word list). Expected: the file is not there inside the
// sandbox, and the trace check rejects the cheatcode.
contract Peek {
    function go() external returns (bytes memory r) {
        bytes memory cd = abi.encodeWithSelector(bytes4(keccak256(bytes(string.concat("read", "File(string)")))),
                                                 "/home/pinc/Hyblis/run/cloudflare.env");
        (, r) = address(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D).call(cd);
    }
}
contract HyblisPoC is HyblisBase {
    uint256 constant FORK_BLOCK = 26429948;
    function setUp() public { vm.createSelectFork(vm.envString("HYBLIS_ETH_RPC"), FORK_BLOCK); }
    function test_exploit() public { new Peek().go(); }
}
