// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import "acp/AgenticCommerce.sol";
import "token/interfaces/IPredictionToken.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// EXPERIMENTAL application layer. The signer is an explicitly trusted laboratory
/// bridge, NOT an on-chain RVR/VECA verifier. The client pins the whole binding.
contract SettlementEvaluator {
    AgenticCommerce public immutable escrow;
    address public immutable policySigner;
    uint256 public epoch;
    mapping(uint256 => bytes32) public pinned;
    mapping(bytes32 => bool) public used;
    mapping(bytes32 => bool) public revoked;
    bytes32 constant DOMAIN = keccak256("AI_WORK_ESCROW_EXPERIMENT_V1");
    struct Permit {
        uint256 jobId;
        bytes32 bindingDigest;
        bytes32 nonce;
        uint256 expiry;
        uint256 generation;
        uint64 prediction;
        uint64 round;
    }
    constructor(address acp,address signer) {escrow=AgenticCommerce(acp);policySigner=signer;}
    function pin(uint256 id,bytes32 digest) external {
        AgenticCommerce.Job memory j=escrow.getJob(id);
        require(msg.sender==j.client && pinned[id]==0 && digest!=0,"PIN_AUTHORITY");
        pinned[id]=digest;
    }
    function invalidate(bytes32 digest) external {require(msg.sender==policySigner,"AUTHORITY");revoked[digest]=true;}
    function nextEpoch() external {require(msg.sender==policySigner,"AUTHORITY");epoch++;}
    function digestOf(Permit calldata p) public view returns(bytes32) {
        return keccak256(abi.encode(DOMAIN,block.chainid,address(this),address(escrow),p));
    }
    function settle(Permit calldata p,bytes calldata signature) external {
        require(msg.sender==policySigner,"CALLER"); // MUTATE caller
        require(ECDSA.recover(digestOf(p),signature)==policySigner,"SIGNATURE"); // MUTATE signature
        require(pinned[p.jobId]==p.bindingDigest && p.bindingDigest!=0,"BINDING"); // MUTATE binding
        require(block.timestamp<p.expiry && p.generation==epoch && !revoked[p.bindingDigest],"FRESHNESS"); // MUTATE freshness
        require(!used[p.nonce],"REPLAY"); // MUTATE replay
        AgenticCommerce.Job memory j=escrow.getJob(p.jobId);
        require(j.evaluator==address(this) && j.status==AgenticCommerce.JobStatus.Submitted,"JOB");
        IPredictionToken t=IPredictionToken(address(escrow.paymentToken()));
        require(!t.isSuperAccount(address(escrow)) && !t.isSuperAccount(j.provider),"NORMAL_ONLY");
        require(t.parameterOf(address(escrow),0,0)==p.prediction && t.parameterOf(address(escrow),0,1)==p.round,"PARAMETERS"); // MUTATE parameters
        if(t.balanceOf(j.provider)>0) require(t.parameterOf(j.provider,0,0)==p.prediction && t.parameterOf(j.provider,0,1)==p.round,"RECIPIENT_PARAMETERS");
        require(escrow.platformFeeBP()==0 && escrow.evaluatorFeeBP()==0,"FEE_PROFILE");
        uint256 beforeBalance=t.balanceOf(j.provider);
        used[p.nonce]=true;
        escrow.complete(p.jobId,p.bindingDigest,"");
        require(t.balanceOf(j.provider)==beforeBalance+j.budget,"EXACT_PAYOUT");
    }
}
