pragma solidity ^0.8.27;

import { InvalidProof, UserNotRegistered, InvalidWithdrawalBalance, InvalidVaultBalance } from "../errors/Errors.sol";
import "./encryptedVaultErrors/encryptedVaultErrors.sol";
import { TransferProof, CreateEncryptedERCParams, EGCT, Point, AmountPCT } from "../types/Types.sol";
import { VaultSettings, VaultWithdrawalProof } from "../types/VaultTypes.sol";
import { EncryptedVaultBalances } from "../Vault/EncryptedVaultBalances.sol";
import { IEncryptedVault } from "./interfaces/IEncryptedVault.sol";
import { IEncryptedVaultBalances } from "./interfaces/IEncryptedVaultBalances.sol";
import { IVaultWithdrawalVerifier } from "../interfaces/verifiers/IVaultWithdrawalVerifier.sol";
import { IRegistrar } from "../interfaces/IRegistrar.sol";
import {BabyJubJub} from "../libraries/BabyJubJub.sol";


contract EncryptedVaultManager {

    ///////////////////////////////////////////////////
    ///                   State Variables            ///
    ///////////////////////////////////////////////////

    /// @notice Address of the registrar contract that manages user registration
    IRegistrar public registrar;

    /// @notice Address of the encrypted vault contract
    IEncryptedVault public immutable encryptedVault;
    IEncryptedVaultBalances public immutable encryptedVaultBalances;
    IVaultWithdrawalVerifier public immutable vaultWithdrawalVerifier;
    
    uint256 public globalNonce;

    mapping(uint256 vaultId => VaultSettings vaultSettings) vaultSettings;
    mapping(uint256 vaultId => address funder) funderOfVault; // Used to see who created the vault
    mapping(uint256 vaultId => address receiver) receiverOfVault; // Used to see who the vault is for
    mapping(address funder => mapping(uint256 tokenId => mapping(address receiver => uint256 vaultId))) vaultsCreatedByFunder;
    mapping(address receiver => mapping(uint256 tokenId => mapping(address funder => uint256 vaultId))) vaultsCreatedForReceiver;

    mapping(address receiver => uint256[] vaultIds) vaultIdsForReceiver;
    mapping(address funder => uint256[] vaultIds) vaultIdsByFunder;


    ///////////////////////////////////////////////////
    ///                   Events                   ///
    ///////////////////////////////////////////////////

    /**
     * @notice Emitted when a vault is created
     * @param funder The address of the funder
     * @param receiver The address of the receiver
     * @param tokenId The ID of the token
     * @param vaultId The ID of the vault
     */
    event VaultCreated(
        address indexed funder,
        address indexed receiver,
        uint256 tokenId,
        uint256 vaultId
    );

    /**
     * @notice Emitted when a vault is funded
     * @param funder The address of the funder 
     * @param vaultId The id of the vault that was funded
     * @param auditorPCT The auditor PCT values of the auditor
     * @param auditor The address of the auditor 
     */
    event VaultFunded(
        address indexed funder,
        uint256 indexed vaultId,
        uint256[7] auditorPCT,
        address indexed auditor
    );


    ///////////////////////////////////////////////////
    ///                   Constructor              ///
    ///////////////////////////////////////////////////

    constructor(address _encryptedVault, address _encryptedVaultBalances, address _registrar, address _vaultWithdrawalVerifier) {
        encryptedVault = IEncryptedVault(_encryptedVault);
        encryptedVaultBalances = IEncryptedVaultBalances(_encryptedVaultBalances);
        vaultWithdrawalVerifier = IVaultWithdrawalVerifier(_vaultWithdrawalVerifier);
        registrar = IRegistrar(_registrar);
        globalNonce = 1;
    }



    ///////////////////////////////////////////////////
    ///                   Functions                ///
    ///////////////////////////////////////////////////

    /**
     * @notice Creates a new vault for a receiver
     * @param receiver The address of the receiver
     * @param tokenId The ID of the token
     * @param distributionAmount The amount of tokens to distribute
     * @param epochLength The length of the epoch
     */
    function createVault(
        address receiver, 
        uint256 tokenId,
        uint256[5] calldata distributionAmount,
        uint256 epochLength
    ) external {
        // Validate user registrations
        {
            if (
                !registrar.isUserRegistered(msg.sender) ||
                !registrar.isUserRegistered(receiver)
            ) {
                revert UserNotRegistered();
            }
        }  
        
        uint256 vaultId = _generateVaultId(receiver, msg.sender, tokenId);
        
        // check if the vault already exists
        if (address(funderOfVault[vaultId]) != address(0)) {
            revert VaultAlreadyExists();
        }

        // check if the receiver is registered
        if (!registrar.isUserRegistered(receiver)) {
            revert UserNotRegistered();
        }

        // check if the funder is registered
        if (!registrar.isUserRegistered(msg.sender)) {
            revert UserNotRegistered();
        }

        // add the vault settings to the state
        _addVaultSettings(vaultId, tokenId, distributionAmount, epochLength);

        // track the vault funder details
        funderOfVault[vaultId] = msg.sender;
        vaultsCreatedByFunder[msg.sender][tokenId][receiver] = vaultId;
        vaultIdsByFunder[msg.sender].push(vaultId);

        // track the vault receiver details
        receiverOfVault[vaultId] = receiver;
        vaultsCreatedForReceiver[receiver][tokenId][msg.sender] = vaultId;
        vaultIdsForReceiver[receiver].push(vaultId);

        emit VaultCreated(msg.sender, receiver, tokenId, vaultId);
    }

    /**
     * @notice Funds a vault
     * @param vaultId The ID of the vault
     * @param proof The proof of the transfer
     * @param balancePCT The balance PCT of the sender
     * @dev This function is used to fund a vault. It will look similar to the existing transfer function that
     *      is used for transferring tokens between users. The difference is that the amount is taken from the
     *      sender's balance and added to the vault's balance.
     * 
     *      This function:
     *      1. Validates that that the sender and receiver are registered
     *      2. Verifies both public keys match the proof
     *      3. Verifies the auditor's public key matches the proof
     *      4. Verifies that the tokenId sent by the sender matches the tokenId of the vault
     *      5. Sends the proof to the encrypted vault to be verified
     *      6. Updates both users' encrypted balances
     */
    function fundVault(
        uint256 vaultId, 
        uint256 tokenId,
        TransferProof memory proof,
        uint256[7] calldata balancePCT
    ) external {
        uint256[32] memory publicInputs = proof.publicSignals;
        address from = msg.sender;


        
        // Validate user registrations
        {
            if (
                !registrar.isUserRegistered(from) ||
                !registrar.isUserRegistered(receiverOfVault[vaultId])
            ) {
                revert UserNotRegistered();
            }
        }

        // Validate public keys 
        {
            uint256[2] memory fromPublicKey = registrar.getUserPublicKey(from);
            uint256[2] memory toPublicKey = registrar.getUserPublicKey(receiverOfVault[vaultId]);
            
            if (
                fromPublicKey[0] != publicInputs[0] ||
                fromPublicKey[1] != publicInputs[1] ||
                toPublicKey[0] != publicInputs[10] ||
                toPublicKey[1] != publicInputs[11]
            ) {
                revert InvalidProof();
            }
        }

        // Validate auditor public key
        {
            if (
                encryptedVault.auditorPublicKey().x != publicInputs[23] ||
                encryptedVault.auditorPublicKey().y != publicInputs[24]
            ) {
                revert InvalidProof();
            }
        }

        // Verify the tokenId matches
        VaultSettings memory _vaultSettings = vaultSettings[vaultId];
        if (_vaultSettings.tokenId != tokenId) {
            revert TokenIdMismatch();
        }
        

        
        // process the vault balance updates
        {

    
            // Process the sender's vault balance
            encryptedVault.fundVault(msg.sender, tokenId, proof, balancePCT); 

            // Process the receiver's vault balance
            // Extract the encrypted amount to add
            
            EGCT memory toEncryptedAmount = EGCT({
                c1: Point({x: publicInputs[12], y: publicInputs[13]}),
                c2: Point({x: publicInputs[14], y: publicInputs[15]})
            });

            // Extract amount PCT
            uint256[7] memory amountPCT;
            for (uint256 i = 0; i < 7; i++) {
                amountPCT[i] = publicInputs[16 + i];
            }

            // Add to the receiver's vault balance
            encryptedVaultBalances.addToVaultBalance(
                vaultId,
                toEncryptedAmount,
                amountPCT
            );
    
        }
        
       
        
        {
            uint256[7] memory auditorPCT;
            for (uint256 i = 0; i < 7; i++) {
                auditorPCT[i] = publicInputs[25 + i];
            }

           emit VaultFunded(from, vaultId, auditorPCT, encryptedVault.auditor());
        }
        
    }

    function withdrawFromVault(
        uint256 vaultId,
        VaultWithdrawalProof memory proof,
        uint256[7] calldata balancePCT
    ) external {
        uint256[50] memory publicInputs = proof.publicSignals;
        VaultSettings storage vault = vaultSettings[vaultId];

        // validate user registration
        {
            if (
                !registrar.isUserRegistered(receiverOfVault[vaultId]) ||
                !registrar.isUserRegistered(funderOfVault[vaultId])
            ) {
                revert UserNotRegistered();
            }
        }

        // validate public keys
        {
            uint256[2] memory receiverPublicKey = registrar.getUserPublicKey(receiverOfVault[vaultId]);
            uint256[2] memory funderPublicKey = registrar.getUserPublicKey(funderOfVault[vaultId]);

            if (
                receiverPublicKey[0] != publicInputs[0] ||
                receiverPublicKey[1] != publicInputs[1] ||
                funderPublicKey[0] != publicInputs[6] ||
                funderPublicKey[1] != publicInputs[7]
            ) {
                revert InvalidProof();
            }

        }

        // validate auditor public key
        {
            if (
                encryptedVault.auditorPublicKey().x != publicInputs[30] ||
                encryptedVault.auditorPublicKey().y != publicInputs[31]
            ) {
                revert InvalidProof();
            }
        }

        // verify the proof
        bool isVerified = vaultWithdrawalVerifier.verifyProof(
            proof.proofPoints.a,
            proof.proofPoints.b,
            proof.proofPoints.c,
            proof.publicSignals
        );
        if (!isVerified) {
            revert InvalidProof();
        }

        // check the vault settings match the proof 
        _checkVaultSettingsValues(vaultId, publicInputs);
        
        // TO DO: ADD CORRECT INDICES
        EGCT memory withdrawalAmountEGCT = EGCT({
            c1: Point({x: publicInputs[8], y: publicInputs[9]}), 
            c2: Point({x: publicInputs[10], y: publicInputs[11]})
        });
        
        // check if this is first withdrawal
        EGCT memory withdrawalTotalEGCT = EGCT({
            c1: Point({x: publicInputs[19], y: publicInputs[20]}), 
            c2: Point({x: publicInputs[21], y: publicInputs[22]})
        });
        if (vault.withdrawalsTotalEGCT.c1.x == 0 && vault.withdrawalsTotalEGCT.c1.y == 0) {
            vault.withdrawalsTotalEGCT = withdrawalAmountEGCT;
        } else {
            // check that user has the correct balance 
            EGCT memory storedWithdrawalTotal = vault.withdrawalsTotalEGCT;

            if (
                withdrawalTotalEGCT.c1.x != storedWithdrawalTotal.c1.x ||
                withdrawalTotalEGCT.c1.y != storedWithdrawalTotal.c1.y ||
                withdrawalTotalEGCT.c2.x != storedWithdrawalTotal.c2.x ||
                withdrawalTotalEGCT.c2.y != storedWithdrawalTotal.c2.y
            ) {
                revert InvalidWithdrawalBalance();
            }
            
            vault.withdrawalsTotalEGCT.c1 = BabyJubJub._add(vault.withdrawalsTotalEGCT.c1, withdrawalAmountEGCT.c1);
            vault.withdrawalsTotalEGCT.c2 = BabyJubJub._add(vault.withdrawalsTotalEGCT.c2, withdrawalAmountEGCT.c2);
        }

        // extract the PCT and replace the existing total
        uint256[7] memory newTotalWithdrawalPCT;
        for (uint256 i = 0; i < 7; i++) {
            newTotalWithdrawalPCT[i] = publicInputs[23 + i];
        }

        vault.withdrawalsTotalPCT = newTotalWithdrawalPCT;

        // perform transaction to decrease the vault balance
        EGCT memory vaultBalanceEGCT = EGCT({
            c1: Point({x: publicInputs[2], y: publicInputs[3]}), 
            c2: Point({x: publicInputs[4], y: publicInputs[5]})
        });

        uint256 vaultBalanceHash = _hashEGCT(vaultBalanceEGCT);
        (bool isValid, uint256 transactionIndex) = encryptedVaultBalances.isVaultBalanceValid(vaultId, vaultBalanceHash);
        if (!isValid) {
            revert InvalidVaultBalance();
        }
        encryptedVaultBalances.subtractFromVaultBalance(vaultId, withdrawalAmountEGCT, balancePCT, transactionIndex);
        
        // perform transaction to increase the user's balance
        {
            uint256[7] memory withdrawalAmountPCT;
            for (uint256 i = 0; i < 7; i++) {
                withdrawalAmountPCT[i] = publicInputs[12 + i];
            }

            encryptedVault.withdrawFromVault(withdrawalAmountEGCT, withdrawalAmountPCT, msg.sender, vault.tokenId);
        }
    }

    function updateVaultSettings(uint256 vaultId, uint256 epochLength, uint256 distributionAmount) external {
        // need a check to ensure the caller is the creater of the vault
    }
    
    function getVaultFunder(uint256 vaultId) external view returns (address) {
        return funderOfVault[vaultId];
    }

    function getVaultReceiver(uint256 vaultId) external view returns (address) {
        return receiverOfVault[vaultId];
    }

    function getVaultTokenId(uint256 vaultId) external view returns (uint256) {
        return vaultSettings[vaultId].tokenId;
    }
    
    function getVault(uint256 vaultId) external view returns (VaultSettings memory) {
        return vaultSettings[vaultId];
    }

    /**
     * @notice Acts as a proxy to the encrypted vault balances contract to get the balance of a vault
     * @param vaultId The ID of the vault
     * @return eGCT The encrypted GCT of the vault
     * @return nonce The nonce of the vault
     * @return amountPCTs The amount PCTs of the vault
     * @return balancePCT The balance PCT of the vault
     * @return transactionIndex The transaction index of the vault
     */
    function getVaultBalance(uint256 vaultId) external view returns (
         EGCT memory eGCT,
        uint256 nonce,
        AmountPCT[] memory amountPCTs,
        uint256[7] memory balancePCT,
        uint256 transactionIndex
    ) {
        return encryptedVaultBalances.vaultBalanceOf(vaultId);
    }

    /**
     * @notice Get the vault created by a funder for a receiver and tokenId
     * @param funder The address of the funder who created the vault
     * @param receiver The address of the receiver
     * @param tokenId The ID of the token
     * @return vaultId The ID of the vault created by the funder for the receiver and tokenId
     */
    function getVaultCreatedBy(address funder, address receiver, uint256 tokenId) external view returns (uint256 vaultId) {
        return vaultsCreatedByFunder[funder][tokenId][receiver];
    }

    /**
     * @notice Get the vault created for a receiver by the sender of the call.
     * @param funder The address of the funder
     * @param receiver The address of the receiver that a vault was created for
     * @param tokenId The ID of the token
     * @return vaultId The ID of the vault created for the receiver
     */
    function getVaultCreatedFor(address funder,address receiver, uint256 tokenId) external view returns (uint256 vaultId){
        return vaultsCreatedForReceiver[receiver][tokenId][funder];
    }

    function getAllVaultsOwnedBy(address user) external view returns (uint256[] memory vaultIds) {
        return vaultIdsForReceiver[user];
    }

    function getVaultsCreatedBy(address funder) external view returns (uint256[] memory vaultIds) {
        return vaultIdsByFunder[funder];
    }


    ///////////////////////////////////////////////////
    ///                   Internal                  ///
    ///////////////////////////////////////////////////

    /**
     * @notice Checks the values of the vault settings
     * @param vaultId The ID of the vault
     * @param inputs The public inputs of the proof
     */
    function _checkVaultSettingsValues(
        uint256 vaultId,
        uint256[50] memory inputs  
    ) internal view {
        VaultSettings memory vault = vaultSettings[vaultId];
        
        require (vault.epochLength == inputs[41], "Invalid epoch length");
        require (vault.startBlock == inputs[42], "Invalid start block");
        require (block.number >= inputs[43], "provided current block is in the future");
        require (vault.distributionAmountPCT[0] == inputs[45], "Invalid distribution amount PCT");
        require (vault.distributionAmountPCT[1] == inputs[46], "Invalid distribution amount PCT");
        require (vault.distributionAmountPCT[2] == inputs[47], "Invalid distribution amount PCT");
        require (vault.distributionAmountPCT[3] == inputs[48], "Invalid distribution amount PCT");
        require (vault.distributionAmountPCT[4] == inputs[49], "Invalid distribution Nonce");
    }
    
    /**
     * @notice adds the vault settings to the state
     * @param vaultId The ID of the vault
     * @param tokenId The ID of the token
     * @param distributionAmount The amount of tokens that are available for distribution at the end of each epoch
     * @param epochLength The length of the epoch
     */
    function _addVaultSettings(
        uint256 vaultId,
        uint256 tokenId,
        uint256[5] calldata distributionAmount,
        uint256 epochLength
    ) internal {
        VaultSettings storage settings = vaultSettings[vaultId];
        settings.isActive = true;
        settings.distributionAmountPCT = distributionAmount;
        settings.nonce = globalNonce;
        settings.epochLength = epochLength;
        settings.startBlock = block.number;
        settings.tokenId = tokenId;

        globalNonce++;
    }
    
    
    /**
     * @notice Generates a unique ID for a vault
     * @param receiver The address of the receiver
     * @param funder The address of the user creating the vault
     * @param tokenId The ID of the token
     * @return vaultId The ID of the vault
     */
    function _generateVaultId(
        address receiver,
        address funder,
        uint256 tokenId
    ) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(receiver, funder, tokenId)));
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