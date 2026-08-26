// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DirectionalOverride {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: Misleading comments due to bidirectional text characters
    // E.g., an attacker uses a Right-To-Left Override character to make code 
    // appear differently than it executes.
    // ⚠️ We use a descriptive comment here instead of the actual RTL character (U+202E) 
    // to prevent tooling issues, but the vulnerability pattern checks for such characters.
    function changeOwner(address newOwner) external {
        // [RTL Override Character] require(msg.sender == owner); 
        // This might look commented out or flipped in some editors, but executes differently.
        owner = newOwner;
    }
}
