// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract StructMappingDelete {
    struct User {
        uint256 balance;
        mapping(address => bool) allowances;
    }

    mapping(address => User) public users;

    function resetUser(address userAddr) external {
        // VULNERABLE: Deleting a struct that contains a mapping
        // The struct is zeroed out, but the nested mapping retains its data.
        // This leads to unexpected state persistence.
        delete users[userAddr];
    }
}
