// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.6.0;

contract ABI {
    function add_encode(address strategy,address _token0,address _token1,uint256 _token0Amount,uint256 _token1Amount,uint256 _minLPAmount) pure public returns(bytes memory) {
        return(abi.encode(strategy,abi.encode(_token0,_token1,_token0Amount,_token1Amount,_minLPAmount)));
    }
    
    function withdraw_encode(address strategy,address _token0,address _token1,uint _whichWantBack)pure public returns(bytes memory){
        return (abi.encode(strategy,abi.encode(_token0,_token1,_whichWantBack)));
    }
}
