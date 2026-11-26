// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import "forge-std/Test.sol";
import "../src/SettlementEvaluator.sol";
import "token/prediction/Router.sol";
import "token/prediction/Core.sol";
import "token/prediction/Permissions.sol";
import "token/prediction/Prediction.sol";
import "token/prediction/PredictionEngine.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
contract EvaluatorControls is Test {
    AgenticCommerce acp; SettlementEvaluator evaluator; IPredictionToken token;
    address client=address(0x111);address provider=address(0x222);address stranger=address(0x333);
    uint256 key;address signer;SettlementEvaluator.Permit permit;
    function setUp() public {
        vm.warp(1700000000);key=vm.envUint("V1_BRIDGE_KEY");signer=vm.addr(key);
        Router router=new Router(address(new Core()),address(new Permissions()),address(new Prediction()),"Synthetic","SYN");
        token=IPredictionToken(address(router));PredictionEngine engine=new PredictionEngine(address(router),73500e8);
        token.setEngine(address(engine));engine.setupToken();
        acp=AgenticCommerce(address(new ERC1967Proxy(address(new AgenticCommerce()),abi.encodeCall(AgenticCommerce.initialize,(address(token),address(this))))));
        evaluator=new SettlementEvaluator(address(acp),signer);
        vm.prank(client);token.mint(client,1000,70000e8,1);
        makeJob(keccak256("exact binding 1"));
        permit=SettlementEvaluator.Permit(1,keccak256("exact binding 1"),bytes32(uint256(1)),1700001000,0,70000e8,1);
    }
    function makeJob(bytes32 binding) internal {
        vm.prank(client);uint256 id=acp.createJob(provider,address(evaluator),1700010000,"Synthetic work",address(0));
        vm.prank(provider);acp.setBudget(id,100,"");vm.prank(client);token.approve(address(acp),100);
        vm.prank(client);acp.fund(id,"");bytes32 deliverable=sha256("2+2=4\n");vm.prank(provider);acp.submit(id,deliverable,"");
        vm.prank(client);evaluator.pin(id,binding);
    }
    function signature(uint256 k) internal view returns(bytes memory) {
        (uint8 v,bytes32 r,bytes32 s)=vm.sign(k,evaluator.digestOf(permit));return abi.encodePacked(r,s,v);
    }
    function pay() internal {bytes memory sig=signature(key);vm.prank(signer);evaluator.settle(permit,sig);}
    function testPositive() public {pay();assertEq(token.balanceOf(provider),100);assertEq(token.balanceOf(address(acp)),0);}
    function testCaller() public {bytes memory sig=signature(key);vm.prank(stranger);vm.expectRevert("CALLER");evaluator.settle(permit,sig);assertEq(token.balanceOf(provider),0);}
    function testSignature() public {bytes memory sig=signature(key+1);vm.prank(signer);vm.expectRevert("SIGNATURE");evaluator.settle(permit,sig);assertEq(token.balanceOf(provider),0);}
    function testBinding() public {permit.bindingDigest=keccak256("other binding");bytes memory sig=signature(key);vm.prank(signer);vm.expectRevert("BINDING");evaluator.settle(permit,sig);}
    function testFreshness() public {vm.warp(permit.expiry);bytes memory sig=signature(key);vm.prank(signer);vm.expectRevert("FRESHNESS");evaluator.settle(permit,sig);}
    function testReplayAcrossJobs() public {pay();makeJob(keccak256("exact binding 2"));permit.jobId=2;permit.bindingDigest=keccak256("exact binding 2");bytes memory sig=signature(key);vm.prank(signer);vm.expectRevert("REPLAY");evaluator.settle(permit,sig);assertEq(token.balanceOf(provider),100);}
    function testParameters() public {vm.prank(stranger);token.mint(address(acp),100,90000e8,1);bytes memory sig=signature(key);vm.prank(signer);vm.expectRevert("PARAMETERS");evaluator.settle(permit,sig);assertEq(token.balanceOf(provider),0);}
    function testRevokedBinding() public {vm.prank(signer);evaluator.invalidate(permit.bindingDigest);bytes memory sig=signature(key);vm.prank(signer);vm.expectRevert("FRESHNESS");evaluator.settle(permit,sig);}
    function testOldEpoch() public {vm.prank(signer);evaluator.nextEpoch();bytes memory sig=signature(key);vm.prank(signer);vm.expectRevert("FRESHNESS");evaluator.settle(permit,sig);}
    function testReverseRace() public {pay();vm.warp(1700010000);vm.expectRevert(AgenticCommerce.WrongStatus.selector);acp.claimRefund(1);assertEq(token.balanceOf(provider),100);}
    // Counterexample: on-chain policy trusts bridge; no native RVR/VECA execution.
    function testTrustedBridgeCanPayWithoutOffchainEvidence() public {pay();assertEq(token.balanceOf(provider),100);}
    function testImmutableRoundConflictNativeToken() public {vm.prank(stranger);token.mint(provider,1,70000e8,2);vm.prank(client);vm.expectRevert("Immutable round conflict");token.transfer(provider,1);assertEq(token.balanceOf(provider),1);}
    function testMutableMergeNativeToken() public {vm.prank(stranger);token.mint(provider,100,90000e8,1);vm.prank(client);token.transfer(provider,100);assertEq(token.parameterOf(provider,0,0),80000e8);assertEq(token.balanceOf(provider),200);}
    function testReferenceZeroBudgetFunding() public {vm.prank(client);uint256 id=acp.createJob(provider,address(evaluator),1700010000,"zero",address(0));vm.prank(client);acp.fund(id,"");assertEq(uint256(acp.getJob(id).status),1);assertEq(acp.getJob(id).budget,0);}
    function testReferenceBudgetChangeWithoutExpectedBudget() public {vm.prank(client);uint256 id=acp.createJob(provider,address(evaluator),1700010000,"budget",address(0));vm.prank(provider);acp.setBudget(id,100,"");vm.prank(client);token.approve(address(acp),200);vm.prank(provider);acp.setBudget(id,200,"");uint256 beforeBal=token.balanceOf(client);vm.prank(client);acp.fund(id,"");assertEq(beforeBal-token.balanceOf(client),200);}
    function testSuperRecipientRefusedByProfile() public {vm.prank(provider);token.convertToSuper();bytes memory sig=signature(key);vm.prank(signer);vm.expectRevert("NORMAL_ONLY");evaluator.settle(permit,sig);}
}
