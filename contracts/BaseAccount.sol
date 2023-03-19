// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./interfaces/IAccount.sol";
import "./interfaces/IEntryPoint.sol";

abstract contract BaseAccount is IAccount {
  //return value in case of signature failure, with no time-range.
  // equivalent to _packValidationData(true,0,0);
  uint256 constant internal SIG_VALIDATION_FAILED = 1;

  /**
    * return the account nonce.
    * subclass should return a nonce value that is used both by _validateAndUpdateNonce, and by the external provider (to read the current nonce)
    */
  function nonce() public view virtual returns (uint256);

  /**
    * return the entryPoint used by this account.
    * subclass should return the current entryPoint used by this account.
    */
  function entryPoint() public view virtual returns (IEntryPoint);

  function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
  external override virtual returns (uint256 validationData) {
    _requireFromEntryPoint();
    validationData = _validateSignature(userOp, userOpHash);
    if (userOp.initCode.length == 0) {
      _validateAndUpdateNonce(userOp); // do not need validate nonce on account creation
    }
    _payPrefund(missingAccountFunds);
  }

  /**
    * ensure the request comes from the known entrypoint.
    */
  function _requireFromEntryPoint() internal virtual view {
    require(msg.sender == address(entryPoint()), "account: not from EntryPoint");
  }

  /**
  * validate the signature is valid for this message.
  * @param userOp validate the userOp.signature field
  * @param userOpHash convenient field: the hash of the request, to check the signature against
  *          (also hashes the entrypoint and chain id)
  * @return validationData signature and time-range of this operation
  *      <20-byte> sigAuthorizer - 0 for valid signature, 1 to mark signature failure,
  *         otherwise, an address of an "authorizer" contract.
  *      <6-byte> validUntil - last timestamp this operation is valid. 0 for "indefinite"
  *      <6-byte> validAfter - first timestamp this operation is valid
  *      If the account doesn't use time-range, it is enough to return SIG_VALIDATION_FAILED value (1) for signature failure.
  *      Note that the validation code cannot use block.timestamp (or block.number) directly.
  */
  function _validateSignature(UserOperation calldata userOp, bytes32 userOpHash)
  internal virtual returns (uint256 validationData);

  /**
  * validate the current nonce matches the UserOperation nonce.
  * then it should update the account's state to prevent replay of this UserOperation.
  * called only if initCode is empty (since "nonce" field is used as "salt" on account creation)
  * @param userOp the op to validate.
  */
  function _validateAndUpdateNonce(UserOperation calldata userOp) internal virtual;

  /**
  * sends to the entrypoint (msg.sender) the missing funds for this transaction.
  * subclass MAY override this method for better funds management
  * (e.g. send to the entryPoint more than the minimum required, so that in future transactions
  * it will not be required to send again)
  * @param missingAccountFunds the minimum value this method should send the entrypoint.
  *  this value MAY be zero, in case there is enough deposit, or the userOp has a paymaster.
  */
  function _payPrefund(uint256 missingAccountFunds) internal virtual {
    if (missingAccountFunds != 0) {
        (bool success,) = payable(msg.sender).call{value : missingAccountFunds, gas : type(uint256).max}("");
        (success);
        //ignore failure (its EntryPoint's job to verify, not account.)
    }
  }
}