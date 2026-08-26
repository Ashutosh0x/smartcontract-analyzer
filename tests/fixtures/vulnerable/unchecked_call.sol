// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UncheckedCall {
    function executeCall(address target, bytes memory data) public {
        // VULNERABLE: Return value of low-level call is not checked
        target.call(data);
    }
}
