// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13 <0.9.0;

// HYBLIS RUNNER FILE (fixed, hashed into every verdict). The runner copies it into each job and
// overwrites any file of the same name. Nothing in here is trusted because of what it prints: the
// verdict engine (runner/trace_verdict.py) reads only forge's raw trace, and it accepts the
// faucet's records only from frames whose code address is HYBLIS_FAUCET (never a delegatecall).
//
// HyblisFaucet: etched at HYBLIS_FAUCET by the harness. The only code allowed to change balances
//   (fund), hand out attacker keys (attackerKey), act as a trusted role (asRole) or move a price
//   feed (setPrice). The engine checks every one of these calls against the task's impact spec.
// HyblisProbe: deployed by the harness and called only from the harness root frame. Its outputs
//   (raw bytes in the trace) are the measurements.

import {StdCheats} from "forge-std/StdCheats.sol";

/// The cheatcodes the runner contracts use (same selectors as forge-std's Vm).
interface IHyblisVm {
    function envString(string calldata name) external view returns (string memory);
    function envBytes32(string calldata name) external view returns (bytes32);
    function envUint(string calldata name) external view returns (uint256);
    function envOr(string calldata name, string calldata delim, address[] calldata defaultValue)
        external view returns (address[] memory);
    function makePersistent(address account) external;
    function revokePersistent(address account) external;
    function etch(address target, bytes calldata code) external;
    function store(address target, bytes32 slot, bytes32 value) external;
    function allowCheatcodes(address account) external;
    function startStateDiffRecording() external;
    function clearMockedCalls() external;
    function createSelectFork(string calldata urlOrAlias, uint256 blockNumber) external returns (uint256);
    function warp(uint256 t) external;
    function roll(uint256 n) external;
    function prank(address sender) external;
    function snapshotState() external returns (uint256);
    function revertToStateAndDelete(uint256 id) external returns (bool);
    function addr(uint256 key) external pure returns (address);
    function mockCall(address callee, bytes calldata data, bytes calldata returnData) external;
}

library HyblisConst {
    address internal constant VM = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;
    address internal constant FAUCET = address(uint160(uint256(keccak256("hyblis.faucet"))));
    bytes32 internal constant SALT_SLOT = keccak256("hyblis.salt");
    bytes32 internal constant NAMES_SLOT = keccak256("hyblis.attacker.names");   // mapping(bytes32 name => index)
    bytes32 internal constant COUNT_SLOT = keccak256("hyblis.attacker.count");   // attacker names handed out
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
}

interface IHyblisERC20 {
    function balanceOf(address) external view returns (uint256);
}

interface IHyblisFeed {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

contract HyblisFaucet is StdCheats {
    IHyblisVm private constant hvm = IHyblisVm(HyblisConst.VM);

    event Funded(address indexed token, address indexed to, uint256 oldBal, uint256 newBal);
    event Attacker(bytes32 indexed nameHash, address runnerAddr, address standaloneAddr);
    event RoleAction(address indexed role, address indexed target, bytes4 selector);
    event PriceSet(address indexed feed, int256 oldAnswer, int256 newAnswer);

    /// Raise `to`'s balance of `token` (address(0) = ETH) by `amount`. Recorded as attacker capital.
    function fund(address token, address to, uint256 amount) external {
        uint256 old = _bal(token, to);
        uint256 target = old + amount;
        if (token == address(0)) deal(to, target);
        else deal(token, to, target);
        uint256 nw = _bal(token, to);
        require(nw == target, "Hyblis faucet: balance not set");
        emit Funded(token, to, old, nw);
    }

    /// A private key for the attacker account `name`, derived from the job's secret salt, so it is
    /// unpredictable before the submission and empty at the pinned block. Also records the address
    /// plain `forge test` gives the same name (makeAddr), which the runner uses to compare runs.
    /// Each distinct name gets the next index (1, 2, ...) and key = keccak256(abi.encode(salt, index)),
    /// so the runner can list every attacker address of the job in advance (the state layer answers
    /// reads of these fresh accounts without a snapshot entry). The same name always gets the same key.
    function attackerKey(string calldata name) external returns (uint256 key) {
        bytes32 slot = HyblisConst.SALT_SLOT;
        bytes32 salt;
        assembly { salt := sload(slot) }
        require(salt != bytes32(0), "Hyblis faucet: no salt");
        bytes32 islot = keccak256(abi.encode(keccak256(bytes(name)), HyblisConst.NAMES_SLOT));
        bytes32 cslot = HyblisConst.COUNT_SLOT;
        uint256 index;
        assembly { index := sload(islot) }
        if (index == 0) {
            assembly {
                index := add(sload(cslot), 1)
                sstore(cslot, index)
                sstore(islot, index)
            }
        }
        key = uint256(keccak256(abi.encode(salt, index))) % HyblisConst.SECP256K1_N;
        if (key == 0) key = 1;
        address a = hvm.addr(key);
        address s = hvm.addr(uint256(keccak256(abi.encodePacked(name))));
        emit Attacker(keccak256(bytes(name)), a, s);
    }

    /// One call as a trusted role. The engine accepts it only if (role, target, function, arguments)
    /// is listed in the task's impact spec (trusted_actions).
    function asRole(address role, address target, bytes calldata data) external returns (bytes memory ret) {
        hvm.prank(role);
        bool ok;
        (ok, ret) = target.call(data);
        if (!ok) assembly { revert(add(ret, 32), mload(ret)) }
        emit RoleAction(role, target, bytes4(data[:4]));
    }

    /// Move a Chainlink-style feed's answer. The engine accepts it only for feeds listed in the spec
    /// and within the spec's bound around the answer at the pinned block. Cleared before measurement.
    function setPrice(address feed, int256 answer) external {
        (uint80 rid, int256 old, uint256 startedAt,, uint80 air) = IHyblisFeed(feed).latestRoundData();
        hvm.mockCall(feed, abi.encodeWithSelector(IHyblisFeed.latestRoundData.selector),
                     abi.encode(rid, answer, startedAt, block.timestamp, air));
        hvm.mockCall(feed, abi.encodeWithSelector(bytes4(0x50d25bcd)), abi.encode(answer));   // latestAnswer()
        emit PriceSet(feed, old, answer);
    }

    function _bal(address token, address who) private view returns (uint256) {
        return token == address(0) ? who.balance : IHyblisERC20(token).balanceOf(who);
    }
}

contract HyblisProbe {
    uint256 private constant READ_GAS = 5_000_000;
    uint256 private constant MAX_VIEW_BYTES = 1024;

    /// Balances of every holder in every token (ETH = address(0); a failed read is 2^256-1), the raw
    /// result of each view, and EXTCODEHASH of every holder and of every watched address.
    function measure(address[] calldata tokens, address[] calldata holders, address[] calldata targets,
                     bytes[] calldata data, address[] calldata codeWatch)
        external view
        returns (uint256[] memory bal, bool[] memory ok, bytes[] memory out, bytes32[] memory holderCode,
                 bytes32[] memory watchCode)
    {
        bal = _balances(tokens, holders);
        (ok, out) = _views(targets, data);
        holderCode = _codes(holders);
        watchCode = _codes(codeWatch);
    }

    function _balances(address[] calldata tokens, address[] calldata holders) private view returns (uint256[] memory bal) {
        bal = new uint256[](tokens.length * holders.length);
        for (uint256 i; i < tokens.length; i++) {
            for (uint256 j; j < holders.length; j++) bal[i * holders.length + j] = _bal(tokens[i], holders[j]);
        }
    }

    function _views(address[] calldata targets, bytes[] calldata data) private view returns (bool[] memory ok, bytes[] memory out) {
        ok = new bool[](targets.length);
        out = new bytes[](targets.length);
        for (uint256 k; k < targets.length; k++) (ok[k], out[k]) = _view(targets[k], data[k]);
    }

    function _codes(address[] calldata accounts) private view returns (bytes32[] memory code) {
        code = new bytes32[](accounts.length);
        for (uint256 j; j < accounts.length; j++) code[j] = accounts[j].codehash;
    }

    function _bal(address token, address who) private view returns (uint256) {
        if (token == address(0)) return who.balance;
        (bool s, bytes memory r) = _view(token, abi.encodeWithSelector(0x70a08231, who));
        return (s && r.length >= 32) ? abi.decode(r, (uint256)) : type(uint256).max;
    }

    /// staticcall with a gas cap that copies at most MAX_VIEW_BYTES of returndata (no returndata bomb)
    function _view(address target, bytes memory cd) private view returns (bool s, bytes memory r) {
        uint256 g = READ_GAS;
        uint256 cap = MAX_VIEW_BYTES;
        assembly {
            s := staticcall(g, target, add(cd, 0x20), mload(cd), 0, 0)
            let n := returndatasize()
            if gt(n, cap) { n := cap }
            r := mload(0x40)
            mstore(r, n)
            returndatacopy(add(r, 0x20), 0, n)
            mstore(0x40, add(add(r, 0x20), and(add(n, 31), not(31))))
        }
    }
}
