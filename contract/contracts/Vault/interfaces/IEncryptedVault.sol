// SPDX-License-Identifier: Ecosystem
pragma solidity 0.8.27;

import { TransferProof, EGCT, Point } from "../../types/Types.sol";
import { VaultSettings, VaultWithdrawalProof } from "../../types/VaultTypes.sol";

/**
 * @title IEncryptedVault
 * @notice Interface for EncryptedVault contract
 */
interface IEncryptedVault {
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
     * @notice Funds a vault
     * @param funder The address of the funder
     * @param tokenId The ID of the token
     * @param proof The input data for the proof
     * @param balancePCT The balance PCT of the sender
     */
    function fundVault(
        address funder,
        uint256 tokenId,
        TransferProof memory proof,
        uint256[7] calldata balancePCT
    ) external;

    /**
     * @notice Withdraws from a vault
     * @param withdrawalAmountEGCT The amount to withdraw
     * @param withdrwalAmountPCT The PCT of the withdrawal amount
     * @param receiver The address of the receiver
     * @param tokenId The ID of the token
     * @dev This function handles the updates to the vault owners non-vault balance.
     */
    function withdrawFromVault(
        EGCT memory withdrawalAmountEGCT, 
        uint256[7] memory withdrwalAmountPCT,
        address receiver,
        uint256 tokenId
    ) external;

    ///////////////////////////////////////////////////
    ///                   View Functions           ///
    ///////////////////////////////////////////////////

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

    /**
     * @notice Gets the auditor's public key
     * @return The auditor's public key
     */
    function auditorPublicKey() external view returns (Point memory);

    /**
     * @notice Gets the auditor's address
     * @return The auditor's address
     */
    function auditor() external view returns (address);

}
