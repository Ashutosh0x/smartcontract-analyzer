// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

contract OracleManipulable {
    IUniswapV2Pair public pair;
    
    constructor(address _pair) {
        pair = IUniswapV2Pair(_pair);
    }
    
    // VULNERABLE: Uses spot price from AMM which can be easily manipulated by flash loans
    function getPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
        return uint256(reserve1) * 1e18 / uint256(reserve0);
    }
}
