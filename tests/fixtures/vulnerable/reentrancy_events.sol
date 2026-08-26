// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ReentrancyEvents {
    mapping(address => uint256) public balances;
    
    event Withdrawn(address indexed user, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // VULNERABLE: External call before state update and event emission
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
        
        // ⚠️ Event emitted after external call can be misleading to off-chain trackers 
        // if reentrancy occurs
        emit Withdrawn(msg.sender, amount);
    }
}
