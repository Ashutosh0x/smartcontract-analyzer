pragma solidity ^0.8.20;
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract SafeVault is ReentrancyGuard {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount; // State update BEFORE call
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
