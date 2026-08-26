// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract EmptyPayableFallback {
    mapping(address => uint256) public donations;

    // VULNERABLE: Empty payable receive function with no logic
    // Users might accidentally send ETH here thinking it updates their balance
    receive() external payable {
        // No state update logic here
    }

    function donate() external payable {
        donations[msg.sender] += msg.value;
    }
}
