// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UnprotectedInitializer {
    address public owner;
    bool public initialized;
    
    // VULNERABLE: Missing initializer modifier
    function initialize() public {
        require(!initialized, "Already initialized");
        owner = msg.sender;
        initialized = true;
    }
}
