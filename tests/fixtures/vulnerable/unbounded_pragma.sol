// SPDX-License-Identifier: MIT
// VULNERABLE: Floating pragma allows compilation with potentially buggy older compilers
pragma solidity >=0.8.20;

contract UnboundedPragma {
    uint256 public value;

    function setValue(uint256 _value) external {
        value = _value;
    }
}
