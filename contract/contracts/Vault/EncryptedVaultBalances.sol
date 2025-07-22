// (c) 2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.27;

import "./encryptedVaultErrors/encryptedVaultErrors.sol";
import { EncryptedUserBalances } from "../EncryptedUserBalances.sol";
import { EncryptedBalance, EGCT, AmountPCT, BalanceHistory } from "../types/Types.sol";
import { BabyJubJub } from "../libraries/BabyJubJub.sol";


contract EncryptedVaultBalances {


    ///////////////////////////////////////////////////
    ///                   State Variables           ///
    ///////////////////////////////////////////////////

    address public vaultManager;
    address public owner;
    bool public vaultManagerSet;

    mapping(uint256 vaultId => EncryptedBalance vaultBalance) vaultBalances;


    ///////////////////////////////////////////////////
    ///                   Modifiers                 ///
    ///////////////////////////////////////////////////

    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert NotOwner();
        }
        _;
    }

    modifier onlyVaultManager() {
        if (msg.sender != vaultManager) {
            revert NotVaultManager();
        }
        _;
    }


     ///////////////////////////////////////////////////
    ///                   Constructor               ///
    ///////////////////////////////////////////////////

    constructor() {
        owner = msg.sender;
    }
    
    
    
    
    ///////////////////////////////////////////////////
    ///                   External                  ///
    ///////////////////////////////////////////////////

    
    function setVaultManager(address _vaultManager) external onlyOwner {
        vaultManager = _vaultManager;
        vaultManagerSet = true;
    }

    function transferOwnership(address _owner) external onlyOwner {
        owner = _owner;
    }


    function addToVaultBalance(
        uint256 vaultId,
        EGCT memory eGCT,
        uint256[7] memory amountPCT
    ) external onlyVaultManager {
        _addToVaultBalance(vaultId, eGCT, amountPCT);
    }


    function subtractFromVaultBalance(
        uint256 vaultId,
        EGCT memory eGCT,
        uint256[7] memory balancePCT,
        uint256 transactionIndex
    ) external onlyVaultManager {
        _subtractFromVaultBalance(vaultId, eGCT, balancePCT, transactionIndex);
    }

    function deleteVaultHistory(
        uint256 vaultId,
        uint256 transactionIndex
    ) external onlyVaultManager {
        _deleteVaultHistory(vaultId, transactionIndex);
    }

    function commitVaultBalance(
        uint256 vaultId
    ) external onlyVaultManager {
        _commitVaultBalance(vaultId);
    }

    function addToVaultHistory(
        uint256 vaultId,
        uint256 tokenId,
        uint256[7] memory amountPCT
    ) external onlyVaultManager {
        _addToVaultHistory(vaultId, amountPCT);
    }
    
    function isVaultBalanceValid(
        uint256 vaultId,
        uint256 balanceHash
    ) external view returns (bool, uint256) {
        return _isVaultBalanceValid(vaultId, balanceHash);
    }
    
    function vaultBalanceOf(
        uint256 vaultId
        ) 
        external view returns (
            EGCT memory eGCT,
            uint256 nonce,
            AmountPCT[] memory amountPCTs,
            uint256[7] memory balancePCT,
            uint256 transactionIndex
        )
    {
        EncryptedBalance storage balance = vaultBalances[vaultId];
        return (
            balance.eGCT,
            balance.nonce,
            balance.amountPCTs,
            balance.balancePCT,
            balance.transactionIndex
        );
    }


    

    ///////////////////////////////////////////////////
    ///                   Internal                  ///
    ///////////////////////////////////////////////////

    /**
     * @notice Adds an encrypted amount to a vault's balance
     * @param vaultId The ID of the vault
     * @param eGCT The ElGamal ciphertext representing the amount to add
     * @param amountPCT The amount PCT for transaction history
     */
    function _addToVaultBalance(
        uint256 vaultId,
        EGCT memory eGCT,
        uint256[7] memory amountPCT
    ) internal {
        EncryptedBalance storage balance = vaultBalances[vaultId];

        // if user balance is not initialized, initialize it
        if (balance.eGCT.c1.x == 0 && balance.eGCT.c1.y == 0) {
            balance.eGCT = eGCT;
        } else {
            // if user balance is already initialized, add the encrypted amount to the balance
            balance.eGCT.c1 = BabyJubJub._add(balance.eGCT.c1, eGCT.c1);
            balance.eGCT.c2 = BabyJubJub._add(balance.eGCT.c2, eGCT.c2);
        }

        // in all the case
        _addToVaultHistory(vaultId, amountPCT);

    }

    /**
     * @notice Subtracts an encrypted amount from a vault's balance
     * @param vaultId The ID of the vault
     * @param eGCT The ElGamal ciphertext representing the amount to subtract
     * @param balancePCT The new balance PCT after subtraction
     * @param transactionIndex The transaction index to delete from history
     */
    function _subtractFromVaultBalance(
        uint256 vaultId,
        EGCT memory eGCT,
        uint256[7] memory balancePCT,
        uint256 transactionIndex
    ) internal {
        EncryptedBalance storage balance = vaultBalances[vaultId];

        balance.eGCT.c1 = BabyJubJub._sub(balance.eGCT.c1, eGCT.c1);
        balance.eGCT.c2 = BabyJubJub._sub(balance.eGCT.c2, eGCT.c2);

        // delete the amount pct from the balance
        _deleteVaultHistory(vaultId, transactionIndex);

        balance.balancePCT = balancePCT;
    }


    /**
     * @notice Adds an amount PCT to a vault's history
     * @param vaultId The ID of the vault
     * @param amountPCT The amount PCT for transaction history
     */
    function _addToVaultHistory(
        uint256 vaultId,
        uint256[7] memory amountPCT
    ) internal {
        EncryptedBalance storage balance = vaultBalances[vaultId];

        uint256 nonce = balance.nonce;
        uint256 balanceHash = _hashEGCT(balance.eGCT);
        balanceHash = uint256(keccak256(abi.encode(balanceHash, nonce)));

        // mark the balance hash as valid
        balance.balanceList[balanceHash] = BalanceHistory({
            index: balance.transactionIndex,
            isValid: true
        });

        // add the amount pct to the balance
        balance.amountPCTs.push(
            AmountPCT({pct: amountPCT, index: balance.transactionIndex})
        );

        balance.transactionIndex++;
    }

    /**
     * @notice Commits the current balance state to the user's history
     * @param vaultId The ID of the vault
     * @dev This function:
     *      1. Calculates a unique hash for the current balance state
     *      2. Marks this hash as valid in the balance history
     *      3. Increments the transaction index
     */
    function _commitVaultBalance(
        uint256 vaultId
    ) internal {
        EncryptedBalance storage balance = vaultBalances[vaultId];

        uint256 nonce = balance.nonce;
        uint256 balanceHash = _hashEGCT(balance.eGCT);
        balanceHash = uint256(keccak256(abi.encode(balanceHash, nonce)));
        
        balance.balanceList[balanceHash] = BalanceHistory({
            index: balance.transactionIndex,
            isValid: true
        });

        balance.transactionIndex++;
    }

    /**
     * @notice Deletes transaction history up to a specific transaction index
     * @param vaultId The ID of the vault
     * @param transactionIndex The transaction index to delete up to
     */
    function _deleteVaultHistory(
        uint256 vaultId,
        uint256 transactionIndex
    ) internal {
        EncryptedBalance storage balance = vaultBalances[vaultId];

        for (uint256 i = balance.amountPCTs.length; i > 0; i--) {
            uint256 index = i - 1;

            if (balance.amountPCTs[index].index <= transactionIndex) {
                balance.amountPCTs[index] = balance.amountPCTs[
                    balance.amountPCTs.length - 1
                ];
                balance.amountPCTs.pop();
            }
        }
        
        balance.nonce++;

        _commitVaultBalance(vaultId);
    }

    /**
     * @notice Checks if a balance hash is valid for a vault
     * @param vaultId The ID of the vault
     * @param balanceHash The hash to validate
     * @return isValid True if the hash is valid, false otherwise
     * @return index The transaction index associated with the hash
     * This is used to validate that a user is using a recent and valid balance
     * in their transactions.
     */
    function _isVaultBalanceValid(
        uint256 vaultId,
        uint256 balanceHash
    ) internal view returns (bool, uint256) {
        uint256 nonce = vaultBalances[vaultId].nonce;
        uint256 hashWithNonce = uint256(keccak256(abi.encode(balanceHash, nonce)));

        return (
            vaultBalances[vaultId].balanceList[hashWithNonce].isValid,
            vaultBalances[vaultId].balanceList[hashWithNonce].index
        );
    }


    /**
     * @notice Calculates a hash of an ElGamal ciphertext
     * @param eGCT The ElGamal ciphertext to hash
     * @return The hash of the ciphertext
     * @dev This function creates a unique identifier for an encrypted balance
     *      by hashing all components of the ElGamal ciphertext.
     */
    function _hashEGCT(EGCT memory eGCT) internal pure returns (uint256) {
        return
            uint256(
                keccak256(
                    abi.encode(eGCT.c1.x, eGCT.c1.y, eGCT.c2.x, eGCT.c2.y)
                )
            );
    }



}
