// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract BatchTransfers {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // VULNERABLE: msg.value reused inside loop for batch operations
    function batchBuy(address[] calldata recipients, uint256 amountPerRecipient) external payable {
        // Issue: check only happens once for the entire batch
        require(msg.value == amountPerRecipient, "Incorrect ETH sent");

        for (uint256 i = 0; i < recipients.length; i++) {
            // Reusing msg.value for multiple token purchases or actions
            // An attacker could use 1x msg.value to buy N times
            // ⚠️ msg.value reuse in loop
            token.transferFrom(address(this), recipients[i], msg.value);
        }
    }
}
