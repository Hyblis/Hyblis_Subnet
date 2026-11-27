// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// TOY PROTOCOL for the Hyblis runner test suite. Nothing here is a real protocol; every bug is
// planted on purpose. Deployed on a local anvil chain by script/Deploy.s.sol.

/// Stands in for an external asset such as USDC (NOT in scope).
contract Token {
    event Transfer(address indexed from, address indexed to, uint256 value);
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    address public immutable minter;
    constructor() { minter = msg.sender; }
    function mint(address to, uint256 a) external { require(msg.sender == minter, "not minter"); balanceOf[to] += a; totalSupply += a; emit Transfer(address(0), to, a); }
    function transfer(address to, uint256 a) external returns (bool) { balanceOf[msg.sender] -= a; balanceOf[to] += a; emit Transfer(msg.sender, to, a); return true; }
    function approve(address, uint256) external pure returns (bool) { return true; }
    function transferFrom(address f, address to, uint256 a) external returns (bool) { balanceOf[f] -= a; balanceOf[to] += a; emit Transfer(f, to, a); return true; }
}

/// In-scope vault implementation (behind Proxy). Planted bugs: withdrawFor (theft), sweep (griefing /
/// insolvency), freeze (freeze). harvest() is a routine keeper action; setFeeSink() is admin-only.
contract VaultImpl {
    Token public token;
    address public feeSink;
    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;
    bool public frozen;
    address public keeper;
    address public owner;
    uint256 public harvests;
    function initialize(Token t, address sink, address keeper_, address owner_) external {
        require(address(token) == address(0)); token = t; feeSink = sink; keeper = keeper_; owner = owner_;
    }
    function deposit(uint256 a) external { token.transferFrom(msg.sender, address(this), a); deposits[msg.sender] += a; totalDeposits += a; }
    function withdraw(uint256 a) external { require(!frozen, "frozen"); deposits[msg.sender] -= a; totalDeposits -= a; token.transfer(msg.sender, a); }
    // BUG 1 (theft): anyone can withdraw anyone's deposit to themselves
    function withdrawFor(address from, uint256 a) external { require(!frozen, "frozen"); deposits[from] -= a; totalDeposits -= a; token.transfer(msg.sender, a); }
    // BUG 2 (griefing): "sweep excess" sends everything to the fee sink, not just the excess
    function sweep() external { token.transfer(feeSink, token.balanceOf(address(this))); }
    // BUG 3 (freeze): anyone can freeze withdrawals
    function freeze() external { frozen = true; }
    function harvest() external { require(msg.sender == keeper, "only keeper"); harvests += 1; }
    function setFeeSink(address s) external { require(msg.sender == owner, "only owner"); feeSink = s; }
    function solvent() external view returns (bool) { return token.balanceOf(address(this)) >= totalDeposits; }
}

contract Proxy {
    bytes32 constant IMPL = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    constructor(address impl) { assembly { sstore(IMPL, impl) } }
    fallback() external payable {
        assembly {
            let impl := sload(IMPL)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(ok) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }
}

/// A contract that already exists on the forked chain and tries to use cheatcodes.
contract Existing {
    function tryCheat() external returns (bool ok, bytes memory r) {
        (ok, r) = address(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D).call(abi.encodeWithSignature("warp(uint256)", 123));
    }
}

/// In scope. Flash-loan protection forbids deposit and withdraw in the same transaction (EIP-1153).
/// BUG: withdrawing after at least one day pays a 10% "loyalty bonus" out of other users' funds.
contract TxGuardVault {
    Token public immutable t;
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public since;
    constructor(Token t_) { t = t_; }
    function deposit(uint256 a) external {
        assembly { tstore(caller(), 1) }
        t.transferFrom(msg.sender, address(this), a); deposits[msg.sender] += a; since[msg.sender] = block.timestamp;
    }
    function withdraw() external {
        uint256 f; assembly { f := tload(caller()) }
        require(f == 0, "deposit and withdraw in one transaction");
        uint256 a = deposits[msg.sender];
        if (block.timestamp >= since[msg.sender] + 1 days) a += a / 10;   // BUG: unfunded bonus
        deposits[msg.sender] = 0;
        t.transfer(msg.sender, a);
    }
}

/// Chainlink-style ETH/USD feed (8 decimals). Not in scope; only its owner (a trusted oracle role) moves it.
contract Feed {
    address public immutable owner; int256 public answer; uint256 public updatedAt;
    constructor(int256 a) { owner = msg.sender; answer = a; updatedAt = block.timestamp; }
    function set(int256 a) external { require(msg.sender == owner, "only oracle"); answer = a; updatedAt = block.timestamp; }
    function latestAnswer() external view returns (int256) { return answer; }
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80) { return (1, answer, updatedAt, updatedAt, 1); }
}

/// In scope. Lends TOKEN against ETH collateral at the feed price, 80% LTV.
/// BUG: a liquidator receives ALL of the user's collateral instead of debt plus a small bonus.
contract Lender {
    Token public immutable token;
    Feed public immutable feed;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public totalDebt;
    constructor(Token t, Feed f) { token = t; feed = f; }
    function depositCollateral() external payable { collateral[msg.sender] += msg.value; }
    function borrow(uint256 a) external {
        debt[msg.sender] += a; totalDebt += a;
        require(healthy(msg.sender), "unhealthy");
        token.transfer(msg.sender, a);
    }
    function healthy(address u) public view returns (bool) {
        (, int256 p,,,) = feed.latestRoundData();
        return debt[u] * 10 <= collateral[u] * uint256(p) / 1e8 * 8;
    }
    function liquidate(address u) external {
        require(!healthy(u), "healthy");
        uint256 d = debt[u]; uint256 c = collateral[u];
        token.transferFrom(msg.sender, address(this), d);
        debt[u] = 0; totalDebt -= d; collateral[u] = 0;
        (bool ok,) = msg.sender.call{value: c}("");
        require(ok, "eth");
    }
}
