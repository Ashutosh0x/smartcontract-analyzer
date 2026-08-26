// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UnsafeSelfdestruct {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: Anyone can call this and destroy the contract
    function destroy() external {
        // Missing require(msg.sender == owner)
        selfdestruct(payable(msg.sender));
    }
}
