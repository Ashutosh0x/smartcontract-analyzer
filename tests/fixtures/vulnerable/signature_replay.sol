// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SignatureReplay {
    mapping(address => uint256) public balances;
    
    // VULNERABLE: Missing nonce and chain ID protection
    function executeTransfer(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) public {
        bytes32 messageHash = keccak256(abi.encodePacked(to, amount));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        address signer = ecrecover(ethSignedMessageHash, v, r, s);
        
        require(balances[signer] >= amount, "Insufficient");
        balances[signer] -= amount;
        balances[to] += amount;
    }
}
