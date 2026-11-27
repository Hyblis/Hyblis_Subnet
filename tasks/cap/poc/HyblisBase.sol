// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13 <0.9.0;

// Hyblis PoC base (researcher-visible). Import it as "./HyblisBase.sol"; the runner always uses its
// own copy of this file. It is a convenience only: it runs inside your PoC's own frames, so Hyblis
// never trusts it. In plain `forge test` (what the bounty platform's judges run) every helper falls
// back to the ordinary forge-std cheatcode, so the file you submit is a normal Foundry test.
//
//   _fund(token, to, amount)      the ONLY way to get capital (address(0) = ETH), up to the task cap.
//                                 deal(token, to, amount) and deal(to, amount) do the same.
//   makeAddr / makeAddrAndKey     your accounts. Under Hyblis they are derived from a per-submission
//                                 secret, so they are unpredictable and empty at the pinned block.
//   _asRole(role, target, data)   one routine call as a trusted role, only if the task lists it.
//   _setPrice(feed, answer)       move a price feed, only for listed feeds and within the task's bound.
//   step1() .. stepN()            optional: if your exploit needs separate transactions, put each one
//                                 in a public stepK() and call them in order from test_exploit().
//                                 Hyblis then runs every step as its own transaction.
//
// _fund, deal, _asRole and _setPrice each run in their own call frame on this contract (hyblisFund,
// hyblisDeal, hyblisAsRole, hyblisSetPrice), under Hyblis and in plain forge test alike, so the runner
// can match the two runs helper by helper. Use them from HyblisPoC itself (setUp(), test_exploit() or a
// step), not from its constructor.

import {Test} from "forge-std/Test.sol";

interface IHyblisRuntime {
    function fund(address token, address to, uint256 amount) external;
    function attackerKey(string calldata name) external returns (uint256 key);
    function asRole(address role, address target, bytes calldata data) external returns (bytes memory);
    function setPrice(address feed, int256 answer) external;
}

interface IHyblisBalance {
    function balanceOf(address) external view returns (uint256);
}

interface IHyblisPriceFeed {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

abstract contract HyblisBase is Test {
    address internal constant HYBLIS_FAUCET = address(uint160(uint256(keccak256("hyblis.faucet"))));

    /// True only under the Hyblis runner (and `hyblis check`).
    function _underHyblis() internal view returns (bool) {
        return HYBLIS_FAUCET.code.length > 0;
    }

    /// Give `to` an extra `amount` of `token` (address(0) = ETH). This is your attacker capital: Hyblis
    /// records it and subtracts it from your measured gain. `to` must be an account you control.
    function _fund(address token, address to, uint256 amount) internal {
        _hyblisHelperFrame();
        HyblisBase(address(this)).hyblisFund(token, to, amount);
    }

    /// forge-std deal(): under Hyblis it funds the difference through the faucet (it may only raise a balance).
    function deal(address token, address to, uint256 give) internal virtual override {
        _hyblisHelperFrame();
        HyblisBase(address(this)).hyblisDeal(token, to, give);
    }

    function deal(address to, uint256 give) internal virtual override {
        _hyblisHelperFrame();
        HyblisBase(address(this)).hyblisDeal(address(0), to, give);
    }

    function makeAddrAndKey(string memory name) internal virtual override returns (address addr, uint256 privateKey) {
        if (!_underHyblis()) return super.makeAddrAndKey(name);
        privateKey = IHyblisRuntime(HYBLIS_FAUCET).attackerKey(name);
        addr = vm.addr(privateKey);
        vm.label(addr, name);
    }

    function makeAddr(string memory name) internal virtual override returns (address addr) {
        (addr,) = makeAddrAndKey(name);
    }

    /// One call to `target` as the trusted `role`. Only routine actions the task lists are accepted;
    /// call it outside any startPrank block.
    function _asRole(address role, address target, bytes memory data) internal returns (bytes memory ret) {
        _hyblisHelperFrame();
        return HyblisBase(address(this)).hyblisAsRole(role, target, data);
    }

    /// Make the Chainlink-style `feed` report `answer` (latestRoundData and latestAnswer). Only feeds the
    /// task lists, within its bound around the answer at the pinned block.
    function _setPrice(address feed, int256 answer) internal {
        _hyblisHelperFrame();
        HyblisBase(address(this)).hyblisSetPrice(feed, answer);
    }

    // ---- the helpers' own call frames: the faucet under Hyblis, forge-std cheatcodes in plain forge test

    function hyblisFund(address token, address to, uint256 amount) external {
        if (_underHyblis()) return IHyblisRuntime(HYBLIS_FAUCET).fund(token, to, amount);
        _hyblisPlainDeal(token, to, _hyblisBalance(token, to) + amount);
    }

    function hyblisDeal(address token, address to, uint256 give) external {
        if (_underHyblis()) {
            uint256 cur = _hyblisBalance(token, to);
            require(give >= cur, "Hyblis: deal may only raise a balance");
            return IHyblisRuntime(HYBLIS_FAUCET).fund(token, to, give - cur);
        }
        _hyblisPlainDeal(token, to, give);
    }

    function hyblisAsRole(address role, address target, bytes calldata data) external returns (bytes memory ret) {
        if (_underHyblis()) return IHyblisRuntime(HYBLIS_FAUCET).asRole(role, target, data);
        vm.prank(role);
        bool ok;
        (ok, ret) = target.call(data);
        if (!ok) assembly { revert(add(ret, 32), mload(ret)) }
    }

    function hyblisSetPrice(address feed, int256 answer) external {
        if (_underHyblis()) return IHyblisRuntime(HYBLIS_FAUCET).setPrice(feed, answer);
        (uint80 rid,, uint256 startedAt,, uint80 air) = IHyblisPriceFeed(feed).latestRoundData();
        vm.mockCall(feed, abi.encodeWithSelector(IHyblisPriceFeed.latestRoundData.selector),
                    abi.encode(rid, answer, startedAt, block.timestamp, air));
        vm.mockCall(feed, abi.encodeWithSelector(bytes4(0x50d25bcd)), abi.encode(answer));   // latestAnswer()
    }

    function _hyblisPlainDeal(address token, address to, uint256 give) private {
        if (token == address(0)) super.deal(to, give);
        else super.deal(token, to, give);
    }

    function _hyblisBalance(address token, address who) private view returns (uint256) {
        return token == address(0) ? who.balance : IHyblisBalance(token).balanceOf(who);
    }

    /// A call to this contract while its constructor runs reaches no code (and would silently do nothing).
    function _hyblisHelperFrame() private view {
        require(address(this).code.length > 0, "Hyblis: use _fund/deal/_asRole/_setPrice after the constructor");
    }
}
