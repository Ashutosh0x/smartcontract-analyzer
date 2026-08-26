// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ERC2771MulticallSpoof {
    address public trustedForwarder;
    mapping(address => uint256) public nonces;

    constructor(address _forwarder) {
        trustedForwarder = _forwarder;
    }

    function isTrustedForwarder(address forwarder) public view returns (bool) {
        return forwarder == trustedForwarder;
    }

    // Extract _msgSender() compatible with ERC2771
    function _msgSender() internal view returns (address sender) {
        if (isTrustedForwarder(msg.sender) && msg.data.length >= 20) {
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            return msg.sender;
        }
    }

    // Example action function
    function doAction() external {
        address sender = _msgSender();
        nonces[sender]++;
    }

    // VULNERABLE: Combining ERC2771 and a naive multicall implementation
    // allows a malicious user to spoof the appended address when calling multicall
    // through the forwarder.
    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool success, bytes memory result) = address(this).delegatecall(data[i]);
            require(success, "Delegatecall failed");
            results[i] = result;
        }
    }
}
