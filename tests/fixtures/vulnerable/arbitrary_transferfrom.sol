// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract ArbitraryTransferFrom {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // VULNERABLE: Arbitrary from parameter in transferFrom
    // Allows anyone to transfer tokens on behalf of 'from' if they gave allowance to this contract
    function transferOnBehalf(address from, address to, uint256 amount) external {
        require(token.transferFrom(from, to, amount), "Transfer failed");
    }
}
