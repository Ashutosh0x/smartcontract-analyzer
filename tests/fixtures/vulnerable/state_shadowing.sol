// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Parent {
    address public owner;

    constructor() {
        owner = msg.sender;
    }
}

contract Child is Parent {
    // VULNERABLE: State variable shadowing
    // This creates a new owner variable instead of overriding the parent's
    address public owner; 

    function changeOwner(address newOwner) external {
        // Modifies the child's owner, but Parent functions still use Parent's owner
        owner = newOwner; 
    }
}
