// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {HyblisBase} from "./HyblisBase.sol";

interface IERC20Like {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

interface IHubLike {
    function getAssetCount() external view returns (uint256);
    function getAssetUnderlyingAndDecimals(uint256) external view returns (address, uint8);
    function remove(uint256 assetId, uint256 amount, address to) external returns (uint256);
}

interface ISpokeLike {
    function getReserveSuppliedAssets(uint256) external view returns (uint256);
    function getUserSuppliedAssets(uint256, address) external view returns (uint256);
    function supply(uint256 reserveId, uint256 amount, address onBehalfOf) external returns (uint256, uint256);
    function withdraw(uint256 reserveId, uint256 amount, address onBehalfOf) external returns (uint256, uint256);
}

// CONTROL invalid_mock: vm.mockCall fakes the main spoke oracle's USDC price. Expect: forge any, policy REJECT, verdict policy:mockCall(address,bytes,bytes).
contract HyblisPoC is HyblisBase {
    uint256 constant FORK_BLOCK = 26508006;
    IHubLike constant HUB_CORE = IHubLike(0xCca852Bc40e560adC3b1Cc58CA5b55638ce826c9);
    ISpokeLike constant MAIN_SPOKE = ISpokeLike(0x94e7A5dCbE816e498b89aB752661904E2F56c485);
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant CORE_USDC_SHARES = 0x531E90a2376902DE8915789Fcc1075e3B0c153E7;   // CORE_USDC_TOKENIZATION_SPOKE
    address constant MAIN_SPOKE_ORACLE = 0x99B2B6CEa9C3D2fd8F4d90f86741C44B212a6127;
    uint256 constant USDC_ASSET = 5;      // CORE hub asset id of USDC
    uint256 constant USDC_RESERVE = 7;    // MAIN_SPOKE reserve id of USDC
    address attacker;

    function setUp() public {
        vm.createSelectFork(vm.envString("HYBLIS_ETH_RPC"), FORK_BLOCK);
        attacker = makeAddr("attacker");
    }

    function test_exploit() public {
        vm.mockCall(MAIN_SPOKE_ORACLE, abi.encodeWithSignature("getReservePrice(uint256)", USDC_RESERVE), abi.encode(uint256(1)));
        assertTrue(true);
    }
}
