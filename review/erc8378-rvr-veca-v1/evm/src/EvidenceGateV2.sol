// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import "acp/AgenticCommerce.sol";
import "token/interfaces/IPredictionToken.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// Separate experimental settlement layer. Signed verifier assertion, NOT a ZK proof.
contract EvidenceGateV2 {
    AgenticCommerce public immutable escrow;
    address public immutable bridge;
    address public immutable verifier;
    address public immutable verifierAuthority;
    bool public verifierRevoked;
    uint256 public epoch;
    mapping(uint256=>bytes32) public pinned;
    mapping(bytes32=>bool) public used;
    bytes32 constant DOMAIN=keccak256("ERC8378_EVIDENCE_GATE_V2");
    bytes32 constant VERIFIED=keccak256("VERIFIED");
    bytes32 constant REPRODUCED=keccak256("REPRODUCED");
    struct Confirmation {
        uint256 jobId;
        address client;
        address recipient;
        address token;
        uint256 amount;
        bytes32 bindingDigest;
        bytes32 evidenceDigest;
        bytes32 policyDigest;
        bytes32 deliverableDigest;
        bytes32 rvrProfile;
        bytes32 rvrReceipt;
        bytes32 vecaClaim;
        bytes32 rvrOutcome;
        bytes32 recomputation;
        bytes32 admission;
        bytes32 nonce;
        uint256 issuedAt;
        uint256 expiry;
        uint256 generation;
        uint64 prediction;
        uint64 round;
    }
    constructor(address acp,address b,address v,address a) {
        require(acp!=address(0)&&b!=address(0)&&v!=address(0)&&a!=address(0),"ZERO");
        require(b!=v&&b!=a&&v!=a,"ROLES");
        escrow=AgenticCommerce(acp);bridge=b;verifier=v;verifierAuthority=a;
    }
    function pin(uint256 jobId,bytes32 digest) external {
        require(msg.sender==escrow.getJob(jobId).client&&pinned[jobId]==0&&digest!=0,"PIN");
        pinned[jobId]=digest;
    }
    function revokeVerifier() external {require(msg.sender==verifierAuthority,"AUTHORITY");verifierRevoked=true;}
    function advanceEpoch() external {require(msg.sender==verifierAuthority,"AUTHORITY");epoch++;}
    function digestOf(Confirmation calldata c) public view returns(bytes32) {
        return keccak256(abi.encode(DOMAIN,block.chainid,address(this),address(escrow),c));
    }
    function settle(Confirmation calldata c,bytes calldata signature) external {
        require(msg.sender==bridge,"CALLER"); // V2GUARD caller
        require(!verifierRevoked,"REVOKED"); // V2GUARD revocation
        require(ECDSA.recover(digestOf(c),signature)==verifier,"VERIFIER_SIGNATURE"); // V2GUARD signature
        require(c.rvrOutcome==VERIFIED&&c.recomputation==REPRODUCED&&c.admission==VERIFIED,"OUTCOMES"); // V2GUARD outcomes
        require(c.evidenceDigest!=0&&c.policyDigest!=0&&c.deliverableDigest!=0&&c.rvrProfile!=0&&c.rvrReceipt!=0&&c.vecaClaim!=0,"EVIDENCE"); // V2GUARD evidence
        require(c.bindingDigest!=0&&pinned[c.jobId]==c.bindingDigest,"BINDING"); // V2GUARD binding
        require(c.issuedAt<=block.timestamp&&block.timestamp<c.expiry&&c.expiry>c.issuedAt&&c.expiry-c.issuedAt<=3600&&c.generation==epoch,"FRESHNESS"); // V2GUARD freshness
        require(c.nonce!=0&&!used[c.nonce],"REPLAY"); // V2GUARD replay
        AgenticCommerce.Job memory j=escrow.getJob(c.jobId);
        require(j.status==AgenticCommerce.JobStatus.Submitted&&j.evaluator==address(this)&&j.hook==address(0)&&block.timestamp<j.expiredAt,"JOB"); // V2GUARD job
        require(j.client==c.client&&j.provider==c.recipient&&j.budget==c.amount&&address(escrow.paymentToken())==c.token,"CONTEXT"); // V2GUARD context
        IPredictionToken t=IPredictionToken(c.token);
        require(!t.isSuperAccount(address(escrow))&&!t.isSuperAccount(j.provider),"NORMAL_ONLY");
        require(t.parameterOf(address(escrow),0,0)==c.prediction&&t.parameterOf(address(escrow),0,1)==c.round,"PARAMETERS");
        if(t.balanceOf(j.provider)>0)require(t.parameterOf(j.provider,0,0)==c.prediction&&t.parameterOf(j.provider,0,1)==c.round,"RECIPIENT_PARAMETERS");
        require(escrow.platformFeeBP()==0&&escrow.evaluatorFeeBP()==0,"FEES");
        uint256 beforeBalance=t.balanceOf(j.provider);
        used[c.nonce]=true;
        escrow.complete(c.jobId,c.bindingDigest,"");
        require(t.balanceOf(j.provider)==beforeBalance+c.amount,"PAYOUT");
    }
}
