// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UnsafeDelegatecall {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABLE: Arbitrary execution with delegatecall
    function execute(address target, bytes memory data) public {
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }
}
