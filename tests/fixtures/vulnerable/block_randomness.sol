// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BlockRandomness {
    address payable public winner;

    function playLottery() external payable {
        require(msg.value == 1 ether, "Must send 1 ETH");

        // VULNERABLE: Using block.timestamp as a source of randomness
        // Miners can manipulate the block timestamp to influence the outcome
        uint256 randomNumber = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 10;

        if (randomNumber == 7) {
            winner = payable(msg.sender);
            (bool success, ) = winner.call{value: address(this).balance}("");
            require(success, "Transfer failed");
        }
    }
}
