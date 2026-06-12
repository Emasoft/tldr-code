// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// A contract that CLAIMS to be ERC20 (declares part of the surface and the
// Transfer/Approval events) but is DELIBERATELY INCOMPLETE: it is missing
// `allowance`, `approve`, and `transferFrom`. An AST-driven ERC20
// conformance rule must flag the missing required members.
contract IncompleteERC20 {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    mapping(address => uint256) private _balances;
    uint256 private _total;

    function totalSupply() external view returns (uint256) {
        return _total;
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _balances[msg.sender] -= value;
        _balances[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }

    // MISSING: allowance(address,address)
    // MISSING: approve(address,uint256)
    // MISSING: transferFrom(address,address,uint256)
}
