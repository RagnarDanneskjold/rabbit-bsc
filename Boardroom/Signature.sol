pragma solidity ^0.4.4;

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `sender` to `recipient` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

interface IPow{
    function mint(address recipient, uint256 amount) external returns (bool);
}

contract Signature{
    address public owner;
    IERC20 public token;
    address public publicKey;
    
    mapping(bytes32 => bool) public isSpend;
    
    event Spend(address _to,uint256 _value);
    
    constructor(address _token,address _key) public{
        owner = msg.sender;
        token = IERC20(_token);
        publicKey = _key;
    }
    
    function spendERC20(address _to,uint256 _value,string memory _rand,bytes _sig) public {
        bytes32 hash = keccak256(_to,_value,_rand);
        require(isSpend[hash] == false);
        (bytes32 r,bytes32 s,byte v) = sigRSV(_sig);
        require(validSignature(hash,r,s,v) == publicKey,"Invalid signature");
        
        IPow(address(token)).mint(_to,_value);
        isSpend[hash] = true;
        emit Spend(_to,_value);
    }
    
    function validSignature(bytes32 _hash,bytes32 r, bytes32 s, byte v1)pure internal returns (address addr){
         uint8 v = uint8(v1) + 27;
         addr = ecrecover(_hash, v, r, s);
    }
    
    function sigRSV(bytes memory _signedString) pure public returns (bytes32,bytes32,byte){
        bytes32  r = bytesToBytes32(slice(_signedString, 0, 32));
        bytes32  s = bytesToBytes32(slice(_signedString, 32, 32));
        byte  v = slice(_signedString, 64, 1)[0];
        return (r,s,v);
    }
    
    function slice(bytes memory data, uint start, uint len)pure internal returns (bytes){
        bytes memory b = new bytes(len);
    
        for(uint i = 0; i < len; i++){
          b[i] = data[i + start];
        }
    
        return b;
    }
    
    function bytesToBytes32(bytes memory source)pure internal returns (bytes32 result) {
        assembly {
            result := mload(add(source, 32))
        }
    }
    
    function setNewOwner(address newOwner) public onlyOwner {
        owner = newOwner;
    }
    
    function setPublicKey(address newKey) public onlyOwner {
        publicKey = newKey;
    }
    
    function withdrawalToken() public onlyOwner{ 
        token.transfer(owner, token.balanceOf(address(this)));
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
}

