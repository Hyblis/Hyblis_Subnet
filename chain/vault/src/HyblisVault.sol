// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title HyblisVault — payout-operator custody for held miner emission (option A)
/// @notice Holds the miner pool (modelled here as an ERC20 "alpha" balance; on
///         Bittensor mainnet the same logic drives the staking precompile) until
///         platform results are known, then pays accepted miners by bounty share.
///
/// Trust model (decided 2026-11-16):
///   * operator  — the owner's payout key. Can pay accepted miners and burn
///                 expired funds. It has NO path to withdraw funds to itself:
///                 there is no generic withdraw, payout recipients cannot be the
///                 operator/guardian, and every payout is logged with a finding
///                 id so it can be checked against the public ledger.
///   * guardian  — a separate key that can pause payouts and rotate the operator.
///                 Rotating the operator is timelocked and announced on-chain.
///   * Anyone can read every movement from events (the public settlement log).
///
/// What the contract does NOT guarantee by itself: that a recipient is the real
/// miner. That is enforced off-chain by cross-checking payout events (finding id
/// + amount) against Hyblis's public ledger. An optional registrar-bound mode
/// (payeeOf) is provided to tighten this.
contract HyblisVault {
    // ---- roles --------------------------------------------------------------
    address public operator;         // owner payout key (option A)
    address public guardian;         // can pause + rotate operator (timelocked)
    address public registrar;        // may register miner payee addresses (optional hardening)

    bool public paused;

    // operator rotation timelock
    address public pendingOperator;
    uint256 public pendingOperatorEta;
    uint256 public constant ROTATE_DELAY = 7 days;

    // optional per-finding payee binding (hotkey hash -> allowed payout address)
    bool public requireRegisteredPayee;
    mapping(bytes32 => address) public payeeOf;

    // accounting
    address public immutable alpha;  // the staked asset (ERC20 model)
    address public constant BURN_SINK = 0x000000000000000000000000000000000000dEaD;

    mapping(bytes32 => bool) public findingPaid; // finding id -> already paid (no double pay)

    // ---- events (the public settlement log) --------------------------------
    event Payout(bytes32 indexed finding, address indexed to, uint256 amount, uint32 period, bytes32 hotkey);
    event Burned(uint256 amount, uint32 period);
    event Paused(bool paused);
    event OperatorRotationQueued(address indexed next, uint256 eta);
    event OperatorRotated(address indexed from, address indexed to);
    event PayeeRegistered(bytes32 indexed hotkey, address indexed payee);
    event RegisteredPayeeRequired(bool required);

    modifier onlyOperator() { require(msg.sender == operator, "not operator"); _; }
    modifier onlyGuardian() { require(msg.sender == guardian, "not guardian"); _; }
    modifier notPaused() { require(!paused, "paused"); _; }

    constructor(address _alpha, address _operator, address _guardian) {
        require(_alpha != address(0) && _operator != address(0) && _guardian != address(0), "zero");
        require(_operator != _guardian, "operator==guardian");
        require(_alpha.code.length > 0, "alpha has no code");
        alpha = _alpha;
        operator = _operator;
        guardian = _guardian;
        registrar = _guardian;
        // On by default: the operator may only pay addresses a separate registrar has bound to a
        // hotkey, so it cannot extract funds to an address it secretly controls (option A guarantee).
        requireRegisteredPayee = true;
    }

    // ---- payouts ------------------------------------------------------------
    /// @notice Pay a batch of accepted findings. Reverts if any recipient is the
    ///         operator or guardian, any finding was already paid, or (in
    ///         registered-payee mode) the recipient is not the hotkey's payee.
    function payout(
        bytes32[] calldata findings,
        address[] calldata to,
        uint256[] calldata amounts,
        uint32[] calldata periods,
        bytes32[] calldata hotkeys
    ) external onlyOperator notPaused {
        uint256 n = findings.length;
        require(to.length == n && amounts.length == n && periods.length == n && hotkeys.length == n, "len");
        for (uint256 i = 0; i < n; i++) {
            address dst = to[i];
            require(dst != address(0) && dst != operator && dst != guardian, "bad recipient");
            require(!findingPaid[findings[i]], "already paid");
            if (requireRegisteredPayee) {
                require(payeeOf[hotkeys[i]] == dst, "payee not registered");
            }
            findingPaid[findings[i]] = true;
            _transfer(dst, amounts[i]);
            emit Payout(findings[i], dst, amounts[i], periods[i], hotkeys[i]);
        }
    }

    /// @notice Burn alpha that has passed the carry-over deadline. Goes to a dead
    ///         address (ERC20 model); on mainnet this maps to recycle/burn of the
    ///         staked asset.
    function burnExpired(uint256 amount, uint32 period) external onlyOperator notPaused {
        _transfer(BURN_SINK, amount);
        emit Burned(amount, period);
    }

    // ---- guardian controls --------------------------------------------------
    function setPaused(bool p) external onlyGuardian { paused = p; emit Paused(p); }

    function queueOperatorRotation(address next) external onlyGuardian {
        require(next != address(0) && next != guardian, "bad next");
        pendingOperator = next;
        pendingOperatorEta = block.timestamp + ROTATE_DELAY;
        emit OperatorRotationQueued(next, pendingOperatorEta);
    }

    function executeOperatorRotation() external onlyGuardian {
        require(pendingOperator != address(0), "none");
        require(block.timestamp >= pendingOperatorEta, "timelock");
        emit OperatorRotated(operator, pendingOperator);
        operator = pendingOperator;
        pendingOperator = address(0);
        pendingOperatorEta = 0;
    }

    // ---- optional registrar-bound payees -----------------------------------
    function setRequireRegisteredPayee(bool req) external onlyGuardian {
        requireRegisteredPayee = req;
        emit RegisteredPayeeRequired(req);
    }

    function setRegistrar(address r) external onlyGuardian { require(r != address(0), "zero"); registrar = r; }

    function registerPayee(bytes32 hotkey, address payee) external {
        require(msg.sender == registrar, "not registrar");
        require(payee != operator && payee != guardian && payee != address(0), "bad payee");
        payeeOf[hotkey] = payee;
        emit PayeeRegistered(hotkey, payee);
    }

    // ---- views --------------------------------------------------------------
    function balance() external view returns (uint256) { return _balanceOf(address(this)); }

    // ---- internal ERC20 (no external libs) ---------------------------------
    function _transfer(address dst, uint256 amount) internal {
        require(alpha.code.length > 0, "alpha has no code");   // a call to a code-less address "succeeds" with empty data
        (bool ok, bytes memory data) = alpha.call(
            abi.encodeWithSelector(0xa9059cbb, dst, amount)); // transfer(address,uint256)
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "transfer failed");
    }

    function _balanceOf(address who) internal view returns (uint256) {
        (bool ok, bytes memory data) = alpha.staticcall(
            abi.encodeWithSelector(0x70a08231, who)); // balanceOf(address)
        require(ok && data.length >= 32, "balanceOf failed");
        return abi.decode(data, (uint256));
    }
}
