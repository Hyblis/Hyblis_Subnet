// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13 <0.9.0;

// HYBLIS RUNNER FILE (fixed, hashed into every verdict). Only data is generated per task
// (HyblisSpec.sol, from impact-spec.json); this program never changes between tasks or jobs.
//
// runner/trace_verdict.py checks that the root frame of this test made EXACTLY the calls below, in
// this order, then reads every measurement from the raw `output` bytes of the root-level probe calls.
// The PoC is a separate contract, so its code only ever runs in frames below the root's children
// [10] (constructor), [12] (setUp) and [13...] (test_exploit, or step1..stepN as separate
// transactions). Each of these root calls is capped at S.POC_GAS: the PoC is deployed inside a capped
// call to this contract's own hyblisDeploy() (a CREATE itself cannot be given a gas cap). Every root
// call returns nothing to Solidity that the PoC could have shaped.

import {HyblisPoC} from "./HyblisPoC.t.sol";
import {HyblisFaucet, HyblisProbe, IHyblisVm, HyblisConst} from "./HyblisRuntime.sol";
import {HyblisSpec as S} from "./HyblisSpec.sol";

contract HyblisHarness {
    IHyblisVm private constant vm = IHyblisVm(HyblisConst.VM);
    address private constant FAUCET = HyblisConst.FAUCET;
    uint256 private constant MAX_STEPS = 16;

    bool public IS_TEST = true;

    function test_hyblis() public {
        string memory rpc = vm.envString("HYBLIS_ETH_RPC");                     // [0] before any PoC code
        bytes32 salt = vm.envBytes32("HYBLIS_SALT");                            // [1] per-job secret
        uint256 steps = vm.envUint("HYBLIS_STEPS");                             // [2] 0 = test_exploit()
        require(steps <= MAX_STEPS, "Hyblis: too many steps");
        HyblisProbe probe = new HyblisProbe();                                   // [3]
        vm.makePersistent(address(probe));                                       // [4]
        vm.etch(FAUCET, type(HyblisFaucet).runtimeCode);                         // [5]
        vm.store(FAUCET, HyblisConst.SALT_SLOT, salt);                           // [6]
        vm.makePersistent(FAUCET);                                               // [7]
        vm.allowCheatcodes(FAUCET);                                              // [8]
        vm.startStateDiffRecording();                                            // [9]
        require(_call(address(this), abi.encodeCall(this.hyblisDeploy, (salt)), S.POC_GAS),
                "Hyblis: PoC deployment failed");                                // [10] constructor, capped
        address poc = _pocAddress(salt);                                         //      address unpredictable
        vm.makePersistent(poc);                                                  // [11] survives the PoC's fork
        _call(poc, abi.encodeWithSignature("setUp()"), S.POC_GAS);               // [12]
        if (steps == 0) {
            _call(poc, abi.encodeWithSelector(S.POC_TEST), S.POC_GAS);           // [13]
        } else {
            for (uint256 k = 1; k <= steps; k++)                                 // [13 .. 12+steps]
                _call(poc, abi.encodeWithSignature(_stepSig(k)), S.POC_GAS);
        }
        _after(rpc, probe, poc);
    }

    /// Root call [10] only (the harness calling itself with a gas cap): deploys the PoC with CREATE2 and
    /// the job's secret salt, so its constructor runs with at most S.POC_GAS.
    function hyblisDeploy(bytes32 salt) external {
        require(msg.sender == address(this), "Hyblis: deploy");
        new HyblisPoC{salt: salt}();
    }

    function _pocAddress(bytes32 salt) private view returns (address) {
        bytes32 h = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(type(HyblisPoC).creationCode)));
        return address(uint160(uint256(h)));
    }

    function _after(string memory rpc, HyblisProbe probe, address poc) private {
        _call(address(vm), abi.encodeWithSignature("stopAndReturnStateDiff()"), 1e6);  // [e]   never copied
        _call(address(vm), abi.encodeWithSignature("stopPrank()"), 1e5);               // [e+1] dangling startPrank
        vm.clearMockedCalls();                                                          // [e+2]
        address[] memory extra = vm.envOr("HYBLIS_ATTACKER_SET", ",", new address[](0)); // [e+3] after the PoC
        (address[] memory holders, address[] memory vt, bytes[] memory vd) = _measureSet(poc, extra);
        vm.startStateDiffRecording();                                                   // [e+4]
        probe.measure(S.tokens(), holders, vt, vd, S.codeWatch());                      // [e+5] POST
        _call(address(vm), abi.encodeWithSignature("stopAndReturnStateDiff()"), 1e6);  // [e+6] read sets
        _probes(true);
        uint256 ts = block.timestamp;
        uint256 bn = block.number;
        vm.revokePersistent(poc);                                                       // baseline: PoC as on chain
        vm.createSelectFork(rpc, S.FORK_BLOCK);                                         // BASELINE: clean fork
        vm.warp(ts);                                                                    // same final time
        vm.roll(bn);                                                                    // and height
        probe.measure(S.tokens(), holders, vt, vd, S.codeWatch());                      // BASELINE measurement
        _probes(false);
    }

    /// Spec holders, then the PoC, then the attacker set; spec views, then every attacker-claim view
    /// for the PoC and each attacker address.
    function _measureSet(address poc, address[] memory extra)
        private pure returns (address[] memory holders, address[] memory vt, bytes[] memory vd)
    {
        address[] memory h = S.holders();
        holders = new address[](h.length + 1 + extra.length);
        for (uint256 i; i < h.length; i++) holders[i] = h[i];
        holders[h.length] = poc;
        for (uint256 i; i < extra.length; i++) holders[h.length + 1 + i] = extra[i];
        (address[] memory st, bytes[] memory sd) = S.views();
        (address[] memory ct, bytes4[] memory cs) = S.claimTemplates();
        uint256 n = st.length + ct.length * (1 + extra.length);
        vt = new address[](n);
        vd = new bytes[](n);
        for (uint256 i; i < st.length; i++) { vt[i] = st[i]; vd[i] = sd[i]; }
        uint256 k = st.length;
        for (uint256 c; c < ct.length; c++) {
            vt[k] = ct[c]; vd[k] = abi.encodeWithSelector(cs[c], poc); k++;
            for (uint256 i; i < extra.length; i++) { vt[k] = ct[c]; vd[k] = abi.encodeWithSelector(cs[c], extra[i]); k++; }
        }
    }

    /// Probes ("can this victim still act?"): POST also records the read set of each probe.
    function _probes(bool post) private {
        (address[] memory actor, address[] memory target, bytes[] memory data, uint256[] memory gas_) = S.probes();
        for (uint256 i; i < actor.length; i++) {
            uint256 snap = vm.snapshotState();
            if (post) vm.startStateDiffRecording();
            vm.prank(actor[i]);
            _call(target[i], data[i], gas_[i]);
            if (post) _call(address(vm), abi.encodeWithSignature("stopAndReturnStateDiff()"), 1e6);
            vm.revertToStateAndDelete(snap);
        }
    }

    /// call with a gas cap; returndata is never copied (no returndata or memory bomb)
    function _call(address to, bytes memory cd, uint256 g) private returns (bool ok) {
        assembly { ok := call(g, to, 0, add(cd, 0x20), mload(cd), 0, 0) }
    }

    function _stepSig(uint256 k) private pure returns (string memory) {
        bytes memory d;
        if (k >= 10) d = abi.encodePacked(bytes1(uint8(48 + k / 10)), bytes1(uint8(48 + k % 10)));
        else d = abi.encodePacked(bytes1(uint8(48 + k)));
        return string(abi.encodePacked("step", d, "()"));
    }
}
