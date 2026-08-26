// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TxOriginAuth {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABLE: Uses tx.origin for authentication
    function withdrawAll(address payable recipient) public {
        require(tx.origin == owner, "Not owner");
        recipient.transfer(address(this).balance);
    }
}
