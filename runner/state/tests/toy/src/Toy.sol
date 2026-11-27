// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Toy contracts for the state-layer end-to-end test. Never deployed anywhere but a local anvil.

contract Token {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    constructor(uint256 supply) {
        balanceOf[msg.sender] = supply;
        totalSupply = supply;
    }

    function transfer(address to, uint256 v) external returns (bool) {
        balanceOf[msg.sender] -= v;
        balanceOf[to] += v;
        return true;
    }

    function approve(address s, uint256 v) external returns (bool) {
        allowance[msg.sender][s] = v;
        return true;
    }
}

contract Vault {
    Token public immutable token;
    address public owner;
    uint256 public counter;
    mapping(uint256 => uint256) public data;
    uint256[] public list;

    constructor(Token t) payable {
        token = t;
        owner = msg.sender;
    }

    function set(uint256 k, uint256 v) external {
        data[k] = v;
        counter++;
    }

    // many slots, so the storage trie has several levels
    function fill(uint256 n) external {
        for (uint256 i = 0; i < n; i++) {
            data[1000 + i] = i + 1;
            list.push(i * 3 + 1);
        }
    }

    receive() external payable {}
}

// creates many accounts, so the state trie has several levels
contract Spray {
    function spray(uint256 n, uint256 seed) external payable {
        for (uint256 i = 0; i < n; i++) {
            payable(address(uint160(uint256(keccak256(abi.encode(seed, i)))))).transfer(1);
        }
    }
}

// never read by the template: only the "outside" test reads it (snapshot miss, then extend)
contract Outside {
    uint256 public secret;
    mapping(address => uint256) public credit;

    function setSecret(uint256 s) external {
        secret = s;
    }

    function give(address a, uint256 v) external {
        credit[a] = v;
    }
}
