// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PrecisionLoss {
    // VULNERABLE: Division before multiplication causes precision loss
    function calculateReward(uint256 amount, uint256 totalAmount, uint256 totalReward) public pure returns (uint256) {
        uint256 ratio = amount / totalAmount;
        return ratio * totalReward;
    }
}
