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


contract PayrollManager {

    ///////////////////////////////////////////////////
    ///                   State Variables           ///
    ///////////////////////////////////////////////////

    /*
        The employee data will be encrypted 
    */
    struct Employee {
        uint256[7] namePCT;
        uint256[7] activeStatusPCT; // Encrypted with the shared public key
        uint256[7] employeeIdPCT; // Encrypted with the employee's public key
        uint256[7] lastPaymentAmountPCT; // Encrypted with the shared public key
        uint256[7] lifetimePaymentTotalPCT; // Encrypted with the shared key; running total of all payments
    }

    struct Business {
        address owner;
        address[] employees;
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
    
    bytes32 public payrollId; // this would be a hash of the payroll transaction data
    uint256 public nonce;
    uint256 public payrollSummaryId;


    mapping(address EmployeeAddress => Employee employeeData) internal employeeRegistry;
    mapping(address BusinessAddress => Business businessData) internal businessRegistry;
    //mapping(uint256 payrollId => mapping(address employeeAddress => Payment paymentData)) public payrollDetailHistory;


    ///////////////////////////////////////////////////
    ///                    Events                   ///
    ///////////////////////////////////////////////////

    event EmployeeAdded(
        address employeeAddress, 
        bytes name
    );

    event EmployeeRemoved(
        address employeeAddress, 
        bytes name
    );
    


    ///////////////////////////////////////////////////
    ///                    Constructor              ///
    ///////////////////////////////////////////////////

    constructor() {
        payrollId = 0;
        payrollSummaryId = 0;
        nonce = 0;
    }

    ///////////////////////////////////////////////////
    ///                    Functions                ///
    ///////////////////////////////////////////////////

    
    function registerNewEmployee(address employeeAddress, bytes calldata name, bytes calldata activeStatusPCT, bytes calldata employeeIdPCT) public {
        Employee memory newEmployee = Employee({
            name: name
        });

        employeeRegistry[employeeAddress] = newEmployee;

        emit EmployeeAdded(employeeAddress, name);
    }
    
    
    //function fetchPayrollSummaryData() public view returns (PayrollSummary memory) {};

    // Fetch employee data; should eventually add modifiers to check if the sender is business or employee
    function fetchEmployeeData(address employeeAddress) public view returns (Employee memory) {
        Employee memory employee = employeeRegistry[employeeAddress];

        return employee;
    }

    // Getter functions for public access
    function getEmployeeData(address employeeAddress) public view returns (Employee memory) {
        return employeeRegistry[employeeAddress];
    }

    function getBusinessData(address businessAddress) public view returns (Business memory) {
        return businessRegistry[businessAddress];
    }


    

    

    
    
    

}