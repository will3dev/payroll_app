pragma solidity 0.8.27;

import { NotOwner, NotVaultManager } from "./encryptedVaultErrors/encryptedVaultErrors.sol";
import { InvalidProof } from "../errors/Errors.sol";
import { TransferProof, CreateEncryptedERCParams, EGCT, Point } from "../types/Types.sol";
import { VaultSettings, VaultWithdrawalProof } from "../types/VaultTypes.sol";
import { EncryptedERC } from "../EncryptedERC.sol";
import { EncryptedVaultBalances } from "../Vault/EncryptedVaultBalances.sol";

contract EncryptedVault is EncryptedERC {
    ///////////////////////////////////////////////////
    ///                   State Variables           ///
    ///////////////////////////////////////////////////

    address public vaultManager;
    bool public vaultManagerSet;

    ///////////////////////////////////////////////////
    ///                   Events                    ///
    ///////////////////////////////////////////////////

    ///////////////////////////////////////////////////
    ///                   Modifiers                 ///
    ///////////////////////////////////////////////////


    modifier onlyVaultManager() {
        if (msg.sender != vaultManager) {
            revert NotVaultManager();
        }
        _;
    }


    ///////////////////////////////////////////////////
    ///                   Constructor               ///
    ///////////////////////////////////////////////////

    constructor(
        CreateEncryptedERCParams memory params
    ) EncryptedERC(params) {

    }



    

    ///////////////////////////////////////////////////
    ///                   External                  ///
    ///////////////////////////////////////////////////

    
    function setVaultManager(address _vaultManager) external onlyOwner {
        vaultManager = _vaultManager;
        vaultManagerSet = true;
    }
    
    
     function fundVault(
        address funder,
        uint256 tokenId,
        TransferProof memory proof,
        uint256[7] calldata balancePCT
    ) external onlyVaultManager {
        uint256[32] memory publicInputs = proof.publicSignals;
        
        // Verify the zero-knowledge proof
        bool isVerified = transferVerifier.verifyProof(
            proof.proofPoints.a,
            proof.proofPoints.b,
            proof.proofPoints.c,
            proof.publicSignals
        );
        if (!isVerified) {
            revert InvalidProof();
        }
        
        // Process the funder's balance
        {
            // Extract the provided balance from the proof
            EGCT memory providedBalance = EGCT({
                c1: Point({x: publicInputs[2], y: publicInputs[3]}),
                c2: Point({x: publicInputs[4], y: publicInputs[5]})
            });

            // Verify the balance is valid
            uint256 balanceHash = _hashEGCT(providedBalance);
            (bool isValid, uint256 transactionIndex) = _isBalanceValid(
                funder,
                tokenId,
                balanceHash
            );
            if (!isValid) {
                revert InvalidProof();
            }

            // Extract the encrypted amount to subtract
            EGCT memory fromEncryptedAmount = EGCT({
                c1: Point({x: publicInputs[6], y: publicInputs[7]}),
                c2: Point({x: publicInputs[8], y: publicInputs[9]})
            });

            // Subtract from the sender's balance
            _subtractFromUserBalance(
                funder,
                tokenId,
                fromEncryptedAmount,
                balancePCT,
                transactionIndex
            );
        }

    }


    function withdrawFromVault(
        EGCT memory withdrawalAmountEGCT, 
        uint256[7] memory withdrwalAmountPCT,
        address receiver,
        uint256 tokenId
    ) external onlyVaultManager {
        _addToUserBalance(receiver, tokenId, withdrawalAmountEGCT, withdrwalAmountPCT);
    }
    
    

    ///////////////////////////////////////////////////
    ///                   Internal                  ///
    ///////////////////////////////////////////////////


   
}
    