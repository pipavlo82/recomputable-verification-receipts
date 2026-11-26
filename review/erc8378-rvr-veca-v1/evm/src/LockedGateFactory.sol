// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import "./EvidenceGateV2.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// Experimental deployment topology: no retained escrow administrator or upgrader.
/// The factory never grants roles to callers; both initial roles are renounced
/// atomically, before anyone can fund a job. No upgrade/delegatecall/execute entry.
contract LockedGateFactory {
    event LockedDeployment(address indexed escrow, address indexed gate, address implementation);
    function create(address token, address bridge, address verifier, address authority)
        external returns (AgenticCommerce escrow, EvidenceGateV2 gate)
    {
        AgenticCommerce implementation = new AgenticCommerce();
        escrow = AgenticCommerce(address(new ERC1967Proxy(address(implementation),
            abi.encodeCall(AgenticCommerce.initialize, (token, address(this))))));
        gate = new EvidenceGateV2(address(escrow), bridge, verifier, authority);
        escrow.renounceRole(escrow.ADMIN_ROLE(), address(this)); // V2FACTORY admin
        escrow.renounceRole(escrow.DEFAULT_ADMIN_ROLE(), address(this)); // V2FACTORY upgrade
        emit LockedDeployment(address(escrow), address(gate), address(implementation));
    }
}
