// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

// Uses a raw ERC20 `transfer` whose boolean return value is silently
// discarded. A SafeERC20-recommendation rule must flag the unchecked return.
contract RawTransferUser {
    function pay(IERC20 token, address to, uint256 amount) external {
        // Return value discarded -> should be flagged (recommend SafeERC20).
        token.transfer(to, amount);
    }

    function pullChecked(IERC20 token, address from, address to, uint256 amount) external {
        // Return value checked via require -> must NOT be flagged.
        require(token.transferFrom(from, to, amount), "transfer failed");
    }
}
