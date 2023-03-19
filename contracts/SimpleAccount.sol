// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./BaseAccount.sol";

contract SimpleAccount is BaseAccount {
  using ECDSA for bytes32;

  //explicit sizes of nonce, to fit a single storage cell with "owner"
  uint96 private _nonce; // 96 bits
  address public owner; // 160 bits

  IEntryPoint private immutable _entryPoint;

  modifier onlyOwner() {
    _onlyOwner();
    _;
  }

  function nonce() public view virtual override returns (uint256) {
    return _nonce;
  }

  function entryPoint() public view virtual override returns (IEntryPoint) {
    return _entryPoint;
  }

  receive() external payable {}

  constructor(IEntryPoint anEntryPoint, address anOwner) {
    _entryPoint = anEntryPoint;
    owner = anOwner;
  }

  function _onlyOwner() internal view {
    //directly from EOA owner, or through the account itself (which gets redirected through execute())
    require(msg.sender == owner || msg.sender == address(this), "only owner");
  }

  function execute(address dest, uint256 value, bytes calldata func) external {
    _requireFromEntryPointOrOwner();
    _call(dest, value, func);
  }

  function _requireFromEntryPointOrOwner() internal view {
    require(msg.sender == address(entryPoint()) || msg.sender == owner, "account: not Owner or EntryPoint");
  }

  function _validateAndUpdateNonce(UserOperation calldata userOp) internal override {
    require(_nonce++ == userOp.nonce, "account: invalid nonce");
  }

  function _validateSignature(UserOperation calldata userOp, bytes32 userOpHash) internal override virtual returns (uint256 validationData) {
    bytes32 hash = userOpHash.toEthSignedMessageHash();
    if (owner != hash.recover(userOp.signature))
      return SIG_VALIDATION_FAILED;
    return 0;
  }

  function _call(address target, uint256 value, bytes memory data) internal {
  (bool success, bytes memory result) = target.call{value: value}(data);
    if(!success) {
      assembly {
        revert(add(result, 32), mload(result))
      }
    }
  }

  function getDeposit() public view returns (uint256) {
    return entryPoint().balanceOf(address(this));
  }

  function addDeposit() public payable {
    entryPoint().depositTo{value: msg.value}(address(this));
  }

  function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlyOwner {
    entryPoint().withdrawTo(withdrawAddress, amount);
  }
}