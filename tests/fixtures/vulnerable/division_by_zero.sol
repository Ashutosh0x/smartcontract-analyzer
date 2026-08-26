// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TokenSplitter {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function splitFunds(address[] calldata recipients, uint256 totalAmount) external {
        require(balances[msg.sender] >= totalAmount, "Insufficient balance");

        // VULNERABLE: Division by zero if recipients.length == 0
        // Will revert entirely when recipients array is empty
        uint256 amountPerRecipient = totalAmount / recipients.length;

        balances[msg.sender] -= totalAmount;
        for (uint256 i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += amountPerRecipient;
        }
    }
}
