// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableAirdrop {
    address[] public recipients;
    mapping(address => uint256) public amounts;

    function addRecipient(address r, uint256 amt) external {
        recipients.push(r);
        amounts[r] = amt;
    }

    // VULNERABLE: external calls inside loop — DoS if any call fails
    function distributeAirdrop() external {
        for (uint256 i = 0; i < recipients.length; i++) {
            address r = recipients[i];
            (bool ok, ) = r.call{value: amounts[r]}("");
            require(ok); // One failure reverts everything
        }
    }
}
