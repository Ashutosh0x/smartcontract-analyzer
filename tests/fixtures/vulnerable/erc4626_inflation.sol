// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract VulnerableVault is ERC20 {
    ERC20 public asset;
    
    constructor(ERC20 _asset) ERC20("Vault Token", "vTOK") {
        asset = _asset;
    }
    
    // VULNERABLE: Classic empty vault inflation attack
    function deposit(uint256 assets) public returns (uint256 shares) {
        if (totalSupply() == 0) {
            shares = assets;
        } else {
            shares = (assets * totalSupply()) / asset.balanceOf(address(this));
        }
        
        _mint(msg.sender, shares);
        asset.transferFrom(msg.sender, address(this), assets);
    }
}
