// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LockedEther {
    mapping(address => uint256) public balances;

    // VULNERABLE: Contract can receive Ether but has no way to withdraw it
    receive() external payable {
        balances[msg.sender] += msg.value;
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
