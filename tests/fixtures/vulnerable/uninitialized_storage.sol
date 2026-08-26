// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UninitializedStorage {
    struct Player {
        uint256 score;
        address id;
    }

    Player public topPlayer; // Slot 0
    mapping(address => Player) public players;

    function updateScore(uint256 newScore) external {
        // VULNERABLE: Prior to solidity 0.8.0, local struct pointers were uninitialized
        // and would point to slot 0. In >0.8.0, this is mostly fixed, but using inline assembly
        // or older compiler versions would allow storage pointer aliasing.
        // We simulate uninitialized pointer by directly overwriting state via assembly
        // or a contrived reference. (Actual uninitialized storage pointers are compile errors in 0.8+)
        
        // Let's model a logic error aliasing state
        Player storage p; 
        assembly {
            p.slot := 0 // Manually pointing to topPlayer slot to simulate the vulnerability
        }
        
        // ⚠️ Overwrites topPlayer.score and topPlayer.id!
        p.score = newScore;
        p.id = msg.sender;
    }
}
