// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

error ValueNotEnough(uint256, uint256);
error NonceAlreadyUsed();
error SignatureFailed();
error AlreadyResolved();

contract Bridge is EIP712, Ownable{
    struct BridgeRequest {
        address tokenInAddress;
        uint256 amountIn;
        address tokenOut;
        uint256 minAmountOut;
        uint96 chainId; /// (20 + 32 + 12) % 32 == 0
        uint256 nonce;
    }

    struct BridgeRequestControl {
        address sender;
        BridgeRequest bridgeRequest;
    }

    mapping(bytes32 bridgeRequestId => BridgeRequestControl bridgeRequestControl) public bridgeRequestControls;
    // mapping(address resolver => mapping(address token => uint256 balance) balances) resolverBalances; // in backend

    constructor() EIP712("bridge", "v1") Ownable(msg.sender){}


    function bridge(BridgeRequest memory bridgeRequest) external payable returns(bytes32 bridgeRequestId){
        if(bridgeRequest.tokenInAddress == address(0)){
            require(
                msg.value >= bridgeRequest.amountIn,
                ValueNotEnough(msg.value, bridgeRequest.amountIn)
            );
        } else {
            IERC20(bridgeRequest.tokenInAddress).transferFrom(msg.sender, address(this), bridgeRequest.amountIn);
        }
        
        BridgeRequestControl memory bridgeRequestControl =  BridgeRequestControl({
            sender: msg.sender,
            bridgeRequest: bridgeRequest
        });

        bridgeRequestId = keccak256(abi.encode(bridgeRequestControl));
        
        require(bridgeRequestControls[bridgeRequestId].sender == address(0), NonceAlreadyUsed());
        
        bridgeRequestControls[bridgeRequestId] = bridgeRequestControl;
    }

    mapping(bytes32 bridgeRequestId => bool resolved) public resolved;

    bytes32 private constant _PERMIT_TYPEHASH_BRIDGE_REQUEST_CONTROL_RESOLVER = keccak256("bridgeRequestControlResolver(address tokenInAddress,uint256 amountIn,address tokenOut,uint256 minAmountOut,uint96 chainId,uint256 nonce,address sender,uint256 amount,address resolver)");
    function resolve(bytes memory signature, uint256 amount,  BridgeRequestControl memory bridgeRequestControl) external payable  {
        bytes32 hash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    _PERMIT_TYPEHASH_BRIDGE_REQUEST_CONTROL_RESOLVER,
                    bridgeRequestControl,
                    amount,
                    msg.sender
                )
            )
        );

        require(ECDSA.recover(hash, signature) == owner(), SignatureFailed());

        if(bridgeRequestControl.bridgeRequest.tokenInAddress == address(0)){
            require(
                msg.value >= amount && amount >= bridgeRequestControl.bridgeRequest.minAmountOut,
                ValueNotEnough(msg.value, bridgeRequestControl.bridgeRequest.minAmountOut)
            );
            payable(bridgeRequestControl.sender).call{value: msg.value};
        } else {
            require(
                amount >= bridgeRequestControl.bridgeRequest.minAmountOut,
                ValueNotEnough(amount, bridgeRequestControl.bridgeRequest.minAmountOut)
            );
            IERC20(bridgeRequestControl.bridgeRequest.tokenInAddress).transferFrom(msg.sender, bridgeRequestControl.sender,  amount);
        }

        require(
            resolved[keccak256(
                abi.encode(bridgeRequestControl)
            )], 
            AlreadyResolved()
        );
    }

    mapping(address resolverAddress => mapping(address tokenAddress => uint256 lastClaim)) public lastClaimsOfResolvers;
    bytes32 private constant _PERMIT_TYPEHASH_CLAIM = keccak256("claim(address resolver,address tokenAddress,uint256 amount,uint256 lastClaim)");
    function claim(bytes memory signature, address tokenAddress, uint256 amount) external{
        bytes32 hash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    _PERMIT_TYPEHASH_CLAIM,
                    msg.sender,
                    tokenAddress,
                    amount,
                    lastClaimsOfResolvers[msg.sender][tokenAddress]
                )
            )
        );

        require(ECDSA.recover(hash, signature) == owner(), SignatureFailed());

        lastClaimsOfResolvers[msg.sender][tokenAddress] += amount;

        if(tokenAddress == address(0)){
            payable(msg.sender).call{value: amount};
        } else {
            IERC20(tokenAddress).transfer(msg.sender, amount);
        }
    }
}
/// ["0x0000000000000000000000000000000000000000", 1000000, "0x0000000000000000000000000000000000000000", 999999, 10,0]