// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

// VULNERABLE: Missing __gap storage variable in an upgradeable contract
// If a new state variable is added in a future upgrade, it could corrupt 
// the storage of child contracts in the inheritance chain.
contract UpgradeableWithoutGap is Initializable {
    uint256 public var1;
    uint256 public var2;

    function initialize() public initializer {
        var1 = 1;
        var2 = 2;
    }
    
    // No uint256[50] private __gap;
}
