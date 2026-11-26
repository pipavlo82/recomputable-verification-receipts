// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import "forge-std/Test.sol";
import "../src/LockedGateFactory.sol";
import "token/prediction/Router.sol";
import "token/prediction/Core.sol";
import "token/prediction/Permissions.sol";
import "token/prediction/Prediction.sol";
import "token/prediction/PredictionEngine.sol";

contract RetainedAdminDrain {
    function proxiableUUID() external pure returns(bytes32) {return bytes32(uint256(keccak256("eip1967.proxy.implementation"))-1);}
    function drain(address token,address to,uint256 amount) external {require(IERC20(token).transfer(to,amount));}
}

contract EvidenceGateControls is Test {
    AgenticCommerce acp; EvidenceGateV2 gate; IPredictionToken token;
    PredictionEngine engine; LockedGateFactory factory;
    address client=address(0x111); address provider=address(0x222); address stranger=address(0x333);
    uint256 bridgeKey; uint256 verifierKey;
    address bridge; address verifier; address authority=address(0x444);
    EvidenceGateV2.Confirmation c;
    bytes32 ffiSubmittedDigest;
    function setUp() public {
        vm.warp(1700000000); bridgeKey=vm.envUint("V1_BRIDGE_KEY"); verifierKey=vm.envUint("V1_VERIFIER_KEY"); bridge=vm.addr(bridgeKey); verifier=vm.addr(verifierKey);
        Router router=new Router(address(new Core()),address(new Permissions()),address(new Prediction()),"Synthetic","SYN");
        token=IPredictionToken(address(router));engine=new PredictionEngine(address(router),73500e8);
        token.setEngine(address(engine));engine.setupToken();router.renounceOwnership();engine.renounceOwnership();
        factory=new LockedGateFactory();(acp,gate)=factory.create(address(token),bridge,verifier,authority);
        vm.prank(client);token.mint(client,1000,70000e8,1);makeJob(keccak256("binding1"));
        c=EvidenceGateV2.Confirmation(1,client,provider,address(token),100,keccak256("binding1"),
            keccak256("evidence"),keccak256("policy"),sha256("2+2=4\n"),keccak256("profile"),
            keccak256("receipt"),keccak256("claim"),keccak256("VERIFIED"),keccak256("REPRODUCED"),
            keccak256("VERIFIED"),bytes32(uint256(1)),1700000000,1700000600,0,70000e8,1);
    }
    function makeJob(bytes32 binding) internal {
        vm.prank(client);uint256 id=acp.createJob(provider,address(gate),1700010000,"Synthetic work",address(0));
        vm.prank(provider);acp.setBudget(id,100,"");vm.prank(client);token.approve(address(acp),100);
        vm.prank(client);acp.fund(id,"");bytes32 deliverable=sha256("2+2=4\n");vm.prank(provider);acp.submit(id,deliverable,"");
        vm.prank(client);gate.pin(id,binding);
    }
    function signHash(bytes32 d,uint256 key) internal pure returns(bytes memory) {
        (uint8 v,bytes32 r,bytes32 s)=vm.sign(key,d);return abi.encodePacked(r,s,v);
    }
    function signature() internal view returns(bytes memory) {return signHash(gate.digestOf(c),verifierKey);}
    function pay() internal {bytes memory sig=signature();vm.prank(bridge);gate.settle(c,sig);}
    function refused(bytes memory sig,bytes memory reason) internal {
        vm.expectRevert(reason);vm.prank(bridge);gate.settle(c,sig);
        assertEq(token.balanceOf(provider),0);assertEq(token.balanceOf(address(acp)),100);assertFalse(gate.used(c.nonce));
    }
    function testPositiveNativeERC8378PaymentOnce() public {pay();assertEq(token.balanceOf(provider),100);assertEq(token.balanceOf(address(acp)),0);}
    function testBridgeWithoutVerificationCannotPay() public {
        vm.prank(bridge);(bool ok,bytes memory errorData)=address(gate).call(abi.encodeCall(gate.settle,(c,bytes(""))));
        assertFalse(ok);assertEq(token.balanceOf(provider),0);assertEq(token.balanceOf(address(acp)),100);assertFalse(gate.used(c.nonce));
        string memory obj="refusal";vm.serializeBool(obj,"payout_call_succeeded",ok);vm.serializeBytes(obj,"revert_data",errorData);
        vm.serializeUint(obj,"provider_before",0);vm.serializeUint(obj,"provider_after",token.balanceOf(provider));
        vm.serializeUint(obj,"escrow_before",100);vm.serializeUint(obj,"escrow_after",token.balanceOf(address(acp)));
        string memory report=vm.serializeBool(obj,"nonce_used",gate.used(c.nonce));
        string memory out=vm.envOr("V2_EVIDENCE_OUT",string("../gate-v2/runs/ffi"));vm.createDir(out,true);vm.writeFile(string.concat(out,"/bridge-refusal.json"),report);
    }
    function testBridgeSignatureCannotReplaceVerifier() public {refused(signHash(gate.digestOf(c),bridgeKey),"VERIFIER_SIGNATURE");}
    function testWrongVerifier() public {refused(signHash(gate.digestOf(c),verifierKey+1),"VERIFIER_SIGNATURE");}
    function testForgedVerifiedFlagHasNoEndpoint() public {vm.prank(bridge);(bool ok,)=address(gate).call(abi.encodeWithSignature("settle(uint256,bool)",1,true));assertFalse(ok);assertEq(token.balanceOf(provider),0);}
    function testEveryBoundFieldSubstitution() public {
        bytes memory sig=signature();bytes memory raw=abi.encode(c);
        for(uint256 i=0;i<21;i++) {
            bytes memory changed=abi.encode(c);
            // Use canonical ABI values: mutate each static field without breaking address/uint64 decoding.
            changed[(i+1)*32-1]=bytes1(uint8(changed[(i+1)*32-1])^1);
            EvidenceGateV2.Confirmation memory altered=abi.decode(changed,(EvidenceGateV2.Confirmation));
            vm.expectRevert("VERIFIER_SIGNATURE");vm.prank(bridge);gate.settle(altered,sig);
            assertEq(token.balanceOf(provider),0);assertEq(token.balanceOf(address(acp)),100);
        }
        assertEq(raw,abi.encode(c));assertFalse(gate.used(c.nonce));
    }
    function testSignedWrongJob() public {c.jobId=2;refused(signature(),"BINDING");}
    function testSignedWrongBinding() public {c.bindingDigest=keccak256("wrong");refused(signature(),"BINDING");}
    function testSignedWrongRecipient() public {c.recipient=stranger;refused(signature(),"CONTEXT");}
    function testSignedWrongToken() public {c.token=stranger;refused(signature(),"CONTEXT");}
    function testSignedWrongAmount() public {c.amount=101;refused(signature(),"CONTEXT");}
    function testSignedWrongClient() public {c.client=stranger;refused(signature(),"CONTEXT");}
    function testZeroEvidenceRefusedEvenWhenSigned() public {c.evidenceDigest=0;refused(signature(),"EVIDENCE");}
    function testZeroPolicyRefusedEvenWhenSigned() public {c.policyDigest=0;refused(signature(),"EVIDENCE");}
    function testRefutedEvenWhenSigned() public {c.rvrOutcome=keccak256("REFUTED");refused(signature(),"OUTCOMES");}
    function testUnverifiableEvenWhenSigned() public {c.admission=keccak256("UNVERIFIABLE");refused(signature(),"OUTCOMES");}
    function testDivergedEvenWhenSigned() public {c.recomputation=keccak256("DIVERGED");refused(signature(),"OUTCOMES");}
    function testCannotRecomputeEvenWhenSigned() public {c.recomputation=keccak256("CANNOT_RECOMPUTE");refused(signature(),"OUTCOMES");}
    function testExpired() public {vm.warp(c.expiry);refused(signature(),"FRESHNESS");}
    function testFuture() public {c.issuedAt=block.timestamp+1;refused(signature(),"FRESHNESS");}
    function testExcessiveLifetime() public {c.expiry=c.issuedAt+3601;refused(signature(),"FRESHNESS");}
    function testZeroNonce() public {c.nonce=0;refused(signature(),"REPLAY");}
    function testOldEpoch() public {vm.prank(authority);gate.advanceEpoch();refused(signature(),"FRESHNESS");}
    function testRevokedVerifier() public {vm.prank(authority);gate.revokeVerifier();refused(signature(),"REVOKED");}
    function testOtherChain() public {bytes memory sig=signature();vm.chainId(31338);refused(sig,"VERIFIER_SIGNATURE");}
    function testOtherGate() public {EvidenceGateV2 other=new EvidenceGateV2(address(acp),bridge,verifier,authority);refused(signHash(other.digestOf(c),verifierKey),"VERIFIER_SIGNATURE");}
    function testOtherEscrowDomain() public {EvidenceGateV2 other=new EvidenceGateV2(address(0x555),bridge,verifier,authority);refused(signHash(other.digestOf(c),verifierKey),"VERIFIER_SIGNATURE");}
    function testDigestMatchesIndependentDomainEncoding() public {assertEq(gate.digestOf(c),keccak256(abi.encode(keccak256("ERC8378_EVIDENCE_GATE_V2"),block.chainid,address(gate),address(acp),c)));}
    function testRepeatPayment() public {bytes memory sig=signature();pay();vm.expectRevert("REPLAY");vm.prank(bridge);gate.settle(c,sig);assertEq(token.balanceOf(provider),100);}
    function testReplayNonceAcrossJobs() public {pay();makeJob(keccak256("binding2"));c.jobId=2;c.bindingDigest=keccak256("binding2");bytes memory sig=signature();vm.expectRevert("REPLAY");vm.prank(bridge);gate.settle(c,sig);assertEq(token.balanceOf(provider),100);assertEq(token.balanceOf(address(acp)),100);}
    function testWrongCaller() public {bytes memory sig=signature();vm.expectRevert("CALLER");vm.prank(stranger);gate.settle(c,sig);assertEq(token.balanceOf(provider),0);}
    function testBridgeCannotRevokeOrAdvance() public {vm.expectRevert("AUTHORITY");vm.prank(bridge);gate.revokeVerifier();vm.expectRevert("AUTHORITY");vm.prank(bridge);gate.advanceEpoch();}
    function testBridgeCannotPinClientBinding() public {vm.expectRevert(bytes("PIN"));vm.prank(bridge);gate.pin(1,keccak256("new"));}
    function testDirectCompleteAndReject() public {vm.expectRevert(AgenticCommerce.Unauthorized.selector);vm.prank(bridge);acp.complete(1,0,"");vm.expectRevert(AgenticCommerce.Unauthorized.selector);vm.prank(bridge);acp.reject(1,0,"");assertEq(token.balanceOf(provider),0);}
    function testFactoryRetainsNoEscrowRoles() public {assertFalse(acp.hasRole(0,address(factory)));assertFalse(acp.hasRole(acp.ADMIN_ROLE(),address(factory)));}
    function testBridgeCannotGrantAdminOrChangeFees() public {vm.expectRevert();vm.prank(bridge);acp.grantRole(0,bridge);vm.expectRevert();vm.prank(bridge);acp.setPlatformFee(100,bridge);}
    function testBridgeCannotUpgradeEscrow() public {RetainedAdminDrain d=new RetainedAdminDrain();vm.expectRevert();vm.prank(bridge);acp.upgradeToAndCall(address(d),abi.encodeCall(d.drain,(address(token),provider,100)));assertEq(token.balanceOf(provider),0);}
    function testFactoryCannotUpgradeEscrow() public {RetainedAdminDrain d=new RetainedAdminDrain();vm.expectRevert();vm.prank(address(factory));acp.upgradeToAndCall(address(d),abi.encodeCall(d.drain,(address(token),provider,100)));}
    function testGateHasNoAdminExecuteOrUpgrade() public {(bool a,)=address(gate).call(abi.encodeWithSignature("execute(address,bytes)",address(acp),abi.encodeCall(acp.complete,(1,bytes32(0),bytes("")))));assertFalse(a);(bool b,)=address(gate).call(abi.encodeWithSignature("upgradeToAndCall(address,bytes)",address(this),bytes("")));assertFalse(b);}
    function testTokenAndEngineOwnershipRenounced() public {vm.expectRevert();token.setEngine(bridge);vm.expectRevert();engine.setupToken();assertEq(token.balanceOf(provider),0);}
    function testBridgeCannotTransferFromEscrow() public {vm.expectRevert();vm.prank(bridge);token.transferFrom(address(acp),provider,100);}
    function testBridgeCannotReinitializeProxyAndGainAuthority() public {vm.expectRevert();vm.prank(bridge);acp.initialize(address(token),bridge);assertFalse(acp.hasRole(0,bridge));}
    function testBridgeCannotChangeProtectedJob() public {vm.expectRevert();vm.prank(bridge);acp.setProvider(1,bridge);vm.expectRevert();vm.prank(bridge);acp.setBudget(1,1,"");assertEq(acp.getJob(1).evaluator,address(gate));}
    function testNonzeroHookRefusedInLockedEscrow() public {vm.expectRevert(AgenticCommerce.HookNotWhitelisted.selector);vm.prank(client);acp.createJob(provider,address(gate),1700010000,"hook bypass",stranger);}
    function testRoleAliasesRejected() public {
        vm.expectRevert("ROLES");new EvidenceGateV2(address(acp),bridge,bridge,authority);
        vm.expectRevert("ROLES");new EvidenceGateV2(address(acp),bridge,verifier,bridge);
        vm.expectRevert("ROLES");new EvidenceGateV2(address(acp),bridge,verifier,verifier);
    }
    function testExpiredJobCannotSettleWithFreshConfirmation() public {vm.warp(1700010000);c.issuedAt=block.timestamp;c.expiry=block.timestamp+600;refused(signature(),"JOB");}
    function testRefundReturnsOnlyToClient() public {vm.warp(1700010000);vm.prank(bridge);acp.claimRefund(1);assertEq(token.balanceOf(client),1000);assertEq(token.balanceOf(provider),0);bytes memory sig=signature();vm.expectRevert();vm.prank(bridge);gate.settle(c,sig);}
    function testRecipientParameterPoisoningFailsClosed() public {vm.prank(stranger);token.mint(provider,1,70000e8,2);bytes memory sig=signature();vm.expectRevert("RECIPIENT_PARAMETERS");vm.prank(bridge);gate.settle(c,sig);assertEq(token.balanceOf(provider),1);assertEq(token.balanceOf(address(acp)),100);assertFalse(gate.used(c.nonce));}
    function testRetainedAdministratorWouldBypassGateCounterexample() public {
        AgenticCommerce unlocked=AgenticCommerce(address(new ERC1967Proxy(address(new AgenticCommerce()),abi.encodeCall(AgenticCommerce.initialize,(address(token),address(this))))));
        EvidenceGateV2 g=new EvidenceGateV2(address(unlocked),bridge,verifier,authority);
        vm.prank(client);uint256 id=unlocked.createJob(provider,address(g),1700010000,"counterexample",address(0));
        vm.prank(provider);unlocked.setBudget(id,100,"");vm.prank(client);token.approve(address(unlocked),100);vm.prank(client);unlocked.fund(id,"");vm.prank(provider);unlocked.submit(id,0,"");
        RetainedAdminDrain d=new RetainedAdminDrain();unlocked.upgradeToAndCall(address(d),abi.encodeCall(d.drain,(address(token),provider,100)));
        assertEq(token.balanceOf(provider),100); // Excluded unlocked topology demonstrably unsafe.
    }
    function testCompromisedVerifierCanLieCounterexample() public {
        c.evidenceDigest=keccak256("no actual offchain evidence");pay();assertEq(token.balanceOf(provider),100);
        // A signature is verifier authorization, not a proof of judgment truth.
    }
    function ffiState(uint256 id) internal view returns(bytes memory) {
        AgenticCommerce.Job memory j=acp.getJob(id);
        return abi.encode(block.chainid,address(acp),address(gate),address(token),j.client,j.provider,id,j.budget,block.timestamp,j.expiredAt,gate.pinned(id),ffiSubmittedDigest);
    }
    function ffiCall(string memory action,uint256 id) internal returns(bytes memory) {
        string[] memory args=new string[](5);args[0]="python";args[1]="-B";
        args[2]="../gate-v2/lab_roundtrip.py";args[3]=action;args[4]=vm.toString(ffiState(id));
        if(vm.envOr("V2_OPTIMIZED",false)) {
            string[] memory optimized=new string[](6);optimized[0]=args[0];optimized[1]="-B";optimized[2]="-O";
            for(uint256 i=2;i<5;i++)optimized[i+1]=args[i];return vm.ffi(optimized);
        }
        return vm.ffi(args);
    }
    function testFFINativeEvidenceVerifiedBeforeActualPayment() public {
        vm.prank(client);uint256 id=acp.createJob(provider,address(gate),1700010000,"ffi exact work",address(0));
        vm.prank(provider);acp.setBudget(id,100,"");vm.prank(client);token.approve(address(acp),100);vm.prank(client);acp.fund(id,"");
        bytes32 delivery=sha256("2+2=4\n");vm.recordLogs();vm.prank(provider);acp.submit(id,delivery,"");
        Vm.Log[] memory submissions=vm.getRecordedLogs();assertEq(submissions.length,1);assertEq(submissions[0].emitter,address(acp));assertEq(submissions[0].topics[0],keccak256("JobSubmitted(uint256,address,bytes32)"));ffiSubmittedDigest=abi.decode(submissions[0].data,(bytes32));
        bytes32 binding=abi.decode(ffiCall("prepare",id),(bytes32));vm.prank(client);gate.pin(id,binding);
        (EvidenceGateV2.Confirmation memory verified,bytes memory sig)=abi.decode(ffiCall("issue",id),(EvidenceGateV2.Confirmation,bytes));
        assertEq(verified.jobId,id);assertEq(verified.bindingDigest,binding);
        vm.recordLogs();vm.prank(bridge);gate.settle(verified,sig);Vm.Log[] memory entries=vm.getRecordedLogs();
        uint256 payments;for(uint256 i=0;i<entries.length;i++)if(entries[i].emitter==address(token)&&entries[i].topics[0]==keccak256("Transfer(address,address,uint256)")){
            assertEq(address(uint160(uint256(entries[i].topics[1]))),address(acp));assertEq(address(uint160(uint256(entries[i].topics[2]))),provider);assertEq(abi.decode(entries[i].data,(uint256)),100);payments++;
        }
        assertEq(payments,1);assertEq(token.balanceOf(provider),100);assertTrue(gate.used(verified.nonce));
        string memory object="payout";
        vm.serializeBytes(object,"confirmation",abi.encode(verified));vm.serializeBytes(object,"signature",sig);
        vm.serializeBytes32(object,"digest",gate.digestOf(verified));vm.serializeAddress(object,"verifier",verifier);
        vm.serializeUint(object,"chain_id",block.chainid);vm.serializeAddress(object,"gate",address(gate));vm.serializeAddress(object,"escrow",address(acp));
        vm.serializeUint(object,"provider_before",0);vm.serializeUint(object,"provider_after",token.balanceOf(provider));
        vm.serializeUint(object,"escrow_before",200);vm.serializeUint(object,"escrow_after",token.balanceOf(address(acp)));
        vm.serializeBool(object,"nonce_used",gate.used(verified.nonce));
        for(uint256 i=0;i<entries.length;i++) {
            string memory name=string.concat("log",vm.toString(i));
            vm.serializeAddress(object,string.concat(name,"_emitter"),entries[i].emitter);
            vm.serializeBytes(object,string.concat(name,"_topics"),abi.encode(entries[i].topics));
            vm.serializeBytes(object,string.concat(name,"_data"),entries[i].data);
        }
        string memory report=vm.serializeUint(object,"log_count",entries.length);
        vm.writeFile(string.concat(vm.envOr("V2_EVIDENCE_OUT",string("../gate-v2/runs/ffi")),"/native-payout.json"),report);
        vm.expectRevert("REPLAY");vm.prank(bridge);gate.settle(verified,sig);assertEq(token.balanceOf(provider),100);
    }
    function testFFIIssuerRejectsDifferentSubmittedDigest() public {
        // The native event's submitted digest, not the bridge's evidence, is authoritative.
        ffiSubmittedDigest=bytes32(uint256(123));assertFalse(abi.decode(ffiCall("check",1),(bool)));assertEq(token.balanceOf(provider),0);
    }
}
