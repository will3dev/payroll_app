// SPDX-License-Identifier: Ecosystem
pragma solidity 0.8.27;

import { EGCT, AmountPCT } from "../../types/Types.sol";

/**
 * @title IEncryptedVaultBalances
 * @notice Interface for EncryptedVaultBalances contract
 */
interface IEncryptedVaultBalances {
    ///////////////////////////////////////////////////
    ///                   External Functions       ///
    ///////////////////////////////////////////////////

    /**
     * @notice Sets the vault manager address
     * @param _vaultManager The address of the vault manager
     */
    function setVaultManager(address _vaultManager) external;

    /**
     * @notice Transfers ownership
     * @param _owner The new owner address
     */
    function transferOwnership(address _owner) external;

    /**
     * @notice Adds an encrypted amount to a vault's balance
     * @param vaultId The ID of the vault
     * @param eGCT The ElGamal ciphertext representing the amount to add
     * @param amountPCT The amount PCT for transaction history
     */
    function addToVaultBalance(
        uint256 vaultId,
        EGCT memory eGCT,
        uint256[7] memory amountPCT
    ) external;

    /**
     * @notice Subtracts an encrypted amount from a vault's balance
     * @param vaultId The ID of the vault
     * @param eGCT The ElGamal ciphertext representing the amount to subtract
     * @param balancePCT The new balance PCT after subtraction
     * @param transactionIndex The transaction index to delete from history
     */
    function subtractFromVaultBalance(
        uint256 vaultId,
        EGCT memory eGCT,
        uint256[7] memory balancePCT,
        uint256 transactionIndex
    ) external;

    /**
     * @notice Deletes transaction history up to a specific transaction index
     * @param vaultId The ID of the vault
     * @param transactionIndex The transaction index to delete up to
     */
    function deleteVaultHistory(
        uint256 vaultId,
        uint256 transactionIndex
    ) external;

    /**
     * @notice Commits the current balance state to the vault's history
     * @param vaultId The ID of the vault
     */
    function commitVaultBalance(
        uint256 vaultId
    ) external;

    /**
     * @notice Adds an amount PCT to a vault's history
     * @param vaultId The ID of the vault
     * @param tokenId The ID of the token
     * @param amountPCT The amount PCT for transaction history
     */
    function addToVaultHistory(
        uint256 vaultId,
        uint256 tokenId,
        uint256[7] memory amountPCT
    ) external;

    /**
     * @notice Checks if a balance hash is valid for a vault
     * @param vaultId The ID of the vault
     * @param balanceHash The hash to validate
     * @return isValid True if the hash is valid, false otherwise
     * @return index The transaction index associated with the hash
     */
    function isVaultBalanceValid(
        uint256 vaultId,
        uint256 balanceHash
    ) external view returns (bool isValid, uint256 index);

    ///////////////////////////////////////////////////
    ///                   View Functions           ///
    ///////////////////////////////////////////////////

    /**
     * @notice Gets the vault balance
     * @param vaultId The ID of the vault
     * @return eGCT The ElGamal ciphertext representing the balance
     * @return nonce The nonce of the balance
     * @return amountPCTs Array of amount PCTs for transaction history
     * @return balancePCT The current balance PCT
     * @return transactionIndex The current transaction index
     */
    function vaultBalanceOf(
        uint256 vaultId
    ) external view returns (
        EGCT memory eGCT,
        uint256 nonce,
        AmountPCT[] memory amountPCTs,
        uint256[7] memory balancePCT,
        uint256 transactionIndex
    );

    /**
     * @notice Gets the vault manager address
     * @return The vault manager address
     */
    function vaultManager() external view returns (address);

    /**
     * @notice Gets the owner address
     * @return The owner address
     */
    function owner() external view returns (address);

    /**
     * @notice Checks if the vault manager is set
     * @return True if the vault manager is set, false otherwise
     */
    function vaultManagerSet() external view returns (bool);
}
