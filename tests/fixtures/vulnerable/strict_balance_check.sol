// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract StrictBalanceCheck {
    uint256 public constant TARGET_BALANCE = 10 ether;
    address public winner;

    function play() external payable {
        // VULNERABLE: Strict equality on balance
        // An attacker can forcefully send Ether via selfdestruct or coinbase
        // to make balance > TARGET_BALANCE, forever locking the game.
        require(address(this).balance == TARGET_BALANCE, "Must reach exactly 10 ETH");
        
        winner = msg.sender;
    }
    
    function claimReward() external {
        require(msg.sender == winner, "Not winner");
        payable(msg.sender).transfer(address(this).balance);
    }
}
