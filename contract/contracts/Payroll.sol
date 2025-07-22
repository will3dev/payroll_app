pragma solidity 0.8.27;

/*
This contract is used to process payroll for a business using the EncryptedERC token.

It will store the payroll data in the contract in an encrypted manner. This would include data such as:
- Employee to business mapping (encrypted)
- Employee data mapping (encrypted) - name, address, last payment amount  
- Payroll data mapping (encrypted) - amount, date, status 

The business will be able to see the payroll data and employees will also be able to view their own data.
Once an employee leaves the business, the business will be able to view the employee data any longer. The business will be able to view the transaction history.

Businesses will want to fetch high level summary data about payroll transaction
Businesses will want to fetch the details of each employee's payroll transaction from a payroll instance

*/
// errors
import {UserNotRegistered, InvalidProof, TransferFailed, UnknownToken, InvalidChainId, InvalidNullifier, ZeroAddress, InvalidAuditorPublicKey, InvalidProofVerification, InvalidPublicKey} from "./errors/Errors.sol";
import {EmployeeDataProof} from "./types/Types.sol";
import {IRegistrar} from "./interfaces/IRegistrar.sol";


import {IEmployeeDataVerifier} from "./interfaces/verifiers/IEmployeeDataVerifier.sol";

contract PayrollManager {

    ///////////////////////////////////////////////////
    ///                   State Variables           ///
    ///////////////////////////////////////////////////

    struct Employee {
        uint256[5] namePCT; // encrypted with the shared key
        uint256[7] employeeIdPCT; // Encrypted with the employee's public key
        uint256[5] lastPaymentAmountPCT; // Encrypted with the shared public key
        uint256[5] lifetimePaymentTotalPCT; // Encrypted with the shared key; running total of all payments
        uint256 bonusIndex; // the starting point to check for bonuses
    }

    struct Bonus {
        uint256[7] amountPCT; // encrypted with the employee's public key
        uint256[7] bonusIdPCT; // encrypted with the bonus' public key
        uint256 nonceUsed;
        bool isClaimed;
    }

    struct Business {
        address owner;
    }

    /*
    // This struct is used to store the summary of a specific round of payroll
    struct PayrollSummary {
        uint256 totalPayrollAmount;
        address[] employees;
        uint256 payrollId;
    }

    struct Payment {
        uint256 amount;
    }

    */

    IEmployeeDataVerifier public EmployeeDataVerifier;
    IRegistrar public registrar;

    
    bytes32 public payrollId; // this would be a hash of the payroll transaction data
    uint256 public nonce;
    uint256 public payrollSummaryId;
    uint256 public bonusIdNonceStarter;


    mapping(address BusinessAddress => mapping(address EmployeeAddress => Employee employeeData)) internal employeeRegistry;
    mapping(address BusinessAddres => mapping(address EmployeeAddress => Bonus[] bonusData)) internal employeeBonus;
    mapping(address BusinessAddress => Business businessData) internal businessRegistry;
    //mapping(uint256 payrollId => mapping(address employeeAddress => Payment paymentData)) public payrollDetailHistory;


    ///////////////////////////////////////////////////
    ///                    Events                   ///
    ///////////////////////////////////////////////////

    event EmployeeAdded(
        address businessAddress,
        address employeeAddress
    );

    event EmployeeStatusUpdated(
        address employeeAddress
    );

    event BonusClaimed(
        address businessAddress,
        address employeeAddress,
        uint256 startIndex
    );

    event BonusIssued(
        address businessAddress,
        address employeeAddress,
        uint256 bonusIndex
    );

    ///////////////////////////////////////////////////
    ///                    Constructor              ///
    ///////////////////////////////////////////////////

    constructor(
        address registrarAddress,
        address employeeDataVerifierAddress
    ) {
        {
            if (
                registrarAddress == address(0) ||
                employeeDataVerifierAddress == address(0)
            ) {
                revert ZeroAddress();
            }

            bonusIdNonceStarter = block.timestamp;

            registrar = IRegistrar(registrarAddress);
            EmployeeDataVerifier = IEmployeeDataVerifier(employeeDataVerifierAddress);
        } 
    }

    ///////////////////////////////////////////////////
    ///                    Functions                ///
    ///////////////////////////////////////////////////

    
    function createNewEmployeeData(address employeeAddress, uint256[5] calldata name, uint256[7] calldata employeeIdPCT) public {
        // Business address will always be the sender
        address businessAddress = msg.sender;

        Employee storage currentEmployee = employeeRegistry[businessAddress][employeeAddress];
        require(currentEmployee.employeeIdPCT[0] == 0, "Employee already exists");

        currentEmployee.employeeIdPCT = employeeIdPCT;
        currentEmployee.namePCT = name;
        currentEmployee.bonusIndex = 0;

        emit EmployeeAdded(businessAddress, employeeAddress);
    }


    /**
     * @notice Issues a bonus to an employee. All bonus details are encrypted using the employee's public key, with the exception of the bonusId
     * Users will be returned the bonus index which they can use to fetch the bonus details.
     * Bonus details include the private key which can then be used to distribute the bonus.
     * @param employeeAddress The address of the employee
     * @param amountPCT The amount of the bonus
     * @param bonusIdPCT The bonus ID
     */
    function issueBonus(
        address employeeAddress, 
        uint256[7] calldata amountPCT, 
        uint256[7] calldata bonusIdPCT
    ) public {
        // Business address will always be the sender
        address businessAddress = msg.sender;

        Employee storage currentEmployee = employeeRegistry[businessAddress][employeeAddress];
        require(currentEmployee.employeeIdPCT[0] != 0, "Employee is not registered");

        Bonus[] storage currentBonuses = employeeBonus[businessAddress][employeeAddress];
        if (currentBonuses.length > 0) {
            uint256 _nonce = currentBonuses[currentBonuses.length - 1].nonceUsed * (currentBonuses.length + 1);

            currentBonuses.push(Bonus({
                amountPCT: amountPCT,
                bonusIdPCT: bonusIdPCT,
                nonceUsed: _nonce,
                isClaimed: false
            }));
        } else {
            currentBonuses.push(Bonus({
                amountPCT: amountPCT,
                bonusIdPCT: bonusIdPCT,
                nonceUsed: bonusIdNonceStarter,
                isClaimed: false
            }));
        }
        emit BonusIssued(businessAddress, employeeAddress, currentBonuses.length - 1);
    }

    

    /**
     * @notice Revokes an employee's data from the payroll system
     * @param businessAddress The address of the business revoking the employee
     * @param proof The proof of the revoke operation
     * @param bonusIndexToClaim The index of the bonus to claim
     */
    function claimBonus(
        address businessAddress, 
        EmployeeDataProof memory proof, 
        uint256 bonusIndexToClaim
    ) public {
        address employeeAddress = msg.sender;
        
        // Check that the bonus has not been claimed and that the index is valid
        require(bonusIndexToClaim < employeeBonus[businessAddress][employeeAddress].length, "Invalid bonus index");
        Bonus memory bonus = employeeBonus[businessAddress][employeeAddress][bonusIndexToClaim];
        require(!bonus.isClaimed, "Bonus already claimed");
        
        // Validate user registration
        {
            if (
                !registrar.isUserRegistered(businessAddress) ||
                !registrar.isUserRegistered(employeeAddress)

            ) {
                revert UserNotRegistered();
            }
        }

        // Validate public keys
        {
            uint256[2] memory businessPublicKey = registrar.getUserPublicKey(businessAddress);
            uint256[2] memory employeePublicKey = registrar.getUserPublicKey(employeeAddress);

            if (
                // TODO: Add checks for the public keys
                businessPublicKey[0] != proof.publicSignals[0] ||
                businessPublicKey[1] != proof.publicSignals[1] ||
                employeePublicKey[0] != proof.publicSignals[4] ||
                employeePublicKey[1] != proof.publicSignals[5]
            ) {
                revert InvalidPublicKey();
            }
        }

        // Check that the correct bonus index is being claimed
        {
            if (
                bonus.bonusIdPCT[0] != proof.publicSignals[15] ||
                bonus.bonusIdPCT[1] != proof.publicSignals[16] ||
                bonus.bonusIdPCT[2] != proof.publicSignals[17] ||
                bonus.bonusIdPCT[3] != proof.publicSignals[18]
            ) {
                revert InvalidProof();
            }
        }

        // Verify the proof
        bool isVerified = EmployeeDataVerifier.verifyProof(
            proof.proofPoints.a,
            proof.proofPoints.b,
            proof.proofPoints.c,
            proof.publicSignals
        );

        if (!isVerified) {
            revert InvalidProof();
        } else {
            // Mark the bonus as claimed
            employeeBonus[businessAddress][employeeAddress][bonusIndexToClaim].isClaimed = true;

            // Mark the bonus to fetch for the user for the next time they fetch their available bonus
            employeeRegistry[businessAddress][employeeAddress].bonusIndex = bonusIndexToClaim + 1;

            emit BonusClaimed(businessAddress, employeeAddress, bonusIndexToClaim);
        }
    }


    /**
     * @notice Fetch all of the unclaimed bonus details for an employee
     * @param businessAddress The address of the business
     * @return firstUnclaimdBonus The first unclaimed bonus
     */
    function fetchFirstUnclaimedBonuses(address businessAddress) public view returns (Bonus memory firstUnclaimdBonus, uint256 bonusIndex) {
        uint256 _bonusIndex = employeeRegistry[businessAddress][msg.sender].bonusIndex;
        Bonus memory unclaimedBonus = employeeBonus[businessAddress][msg.sender][_bonusIndex];

        return ( unclaimedBonus, _bonusIndex );
    }


    /**
     * @notice Fetch the employee data for a specific employee
     * @param employeeAddress The address of the employee
     * @param businessAddress The address of the business
     * @return employee The employee data
     */
    function fetchPrivateEmployeeData(address employeeAddress, address businessAddress) public view returns (Employee memory) {
        Employee memory employee = employeeRegistry[businessAddress][employeeAddress];

        return employee;
    }


    function fetchLastBonusNonce(address businessAddress, address employeeAddress) public view returns(uint256 lastBonusNonce) {
        uint256 bonusListLength = employeeBonus[businessAddress][employeeAddress].length;
        if (bonusListLength == 0) {
            return bonusIdNonceStarter;
        } else {
            return employeeBonus[businessAddress][employeeAddress][bonusListLength - 1].nonceUsed;
        }
    }

}