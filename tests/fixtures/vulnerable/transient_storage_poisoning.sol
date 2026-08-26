// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract TransientStoragePoisoning {
    // VULNERABLE: Transient storage is not cleared appropriately, 
    // potentially leaking state across composable calls in the same transaction
    function setTemporaryAdmin(address admin) public {
        assembly {
            tstore(0, admin)
        }
    }
    
    function executeAdminAction() public {
        address admin;
        assembly {
            admin := tload(0)
        }
        require(admin == msg.sender, "Not transient admin");
        // Do something privileged
        // BUT doesn't clear the tstore(0, 0), so it remains set for the rest of the TX!
    }
}
