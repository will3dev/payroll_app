import { ethers } from "hardhat";
import { encryptMessageEcdh, decryptMessageEcdh, generateKeyPair, type EncryptedMessage } from "./ecdh";

// Example: How to encrypt payroll data for employees using their registered public keys

interface PayrollData {
    employeeAddress: string;
    amount: string;
    period: string;
}

export class PayrollEncryption {
    private registrarContract: any;

    constructor(registrarAddress: string, signer: ethers.Signer) {
        // Initialize the Registrar contract
        const registrarABI = [
            "function getPublicKey(address user) view returns (uint256[2])",
            "function isRegistered(address user) view returns (bool)"
        ];
        this.registrarContract = new ethers.Contract(registrarAddress, registrarABI, signer);
    }

    /**
     * Encrypt payroll data for a specific employee
     */
    async encryptForEmployee(
        employeeAddress: string,
        payrollData: PayrollData,
        businessPrivateKey: bigint
    ): Promise<EncryptedMessage> {
        // Check if employee is registered
        const isRegistered = await this.registrarContract.isRegistered(employeeAddress);
        if (!isRegistered) {
            throw new Error(`Employee ${employeeAddress} is not registered`);
        }

        // Get employee's public key from the Registrar
        const publicKeyArray = await this.registrarContract.getPublicKey(employeeAddress);
        const employeePublicKey: [bigint, bigint] = [
            BigInt(publicKeyArray[0].toString()),
            BigInt(publicKeyArray[1].toString())
        ];

        // Serialize payroll data
        const message = JSON.stringify(payrollData);

        // Encrypt the message
        return encryptMessageEcdh(employeePublicKey, businessPrivateKey, message);
    }

    /**
     * Decrypt payroll data (employee side)
     */
    decryptPayrollData(
        businessPublicKey: [bigint, bigint],
        employeePrivateKey: bigint,
        encryptedMessage: EncryptedMessage
    ): PayrollData {
        // Decrypt the message
        const decryptedMessage = decryptMessageEcdh(
            businessPublicKey,
            employeePrivateKey,
            encryptedMessage
        );

        // Parse the JSON data
        return JSON.parse(decryptedMessage) as PayrollData;
    }

    /**
     * Encrypt payroll data for multiple employees (batch)
     */
    async encryptBatchPayroll(
        payrollBatch: PayrollData[],
        businessPrivateKey: bigint
    ): Promise<{ [employeeAddress: string]: EncryptedMessage }> {
        const encryptedBatch: { [employeeAddress: string]: EncryptedMessage } = {};

        for (const payrollData of payrollBatch) {
            try {
                const encrypted = await this.encryptForEmployee(
                    payrollData.employeeAddress,
                    payrollData,
                    businessPrivateKey
                );
                encryptedBatch[payrollData.employeeAddress] = encrypted;
            } catch (error) {
                console.error(`Failed to encrypt for ${payrollData.employeeAddress}:`, error);
                // Continue with other employees
            }
        }

        return encryptedBatch;
    }
}

// Usage example
export async function exampleUsage() {
    // Generate key pairs for testing
    const businessKeys = generateKeyPair();
    const employeeKeys = generateKeyPair();

    console.log("Business Public Key:", businessKeys.publicKey);
    console.log("Employee Public Key:", employeeKeys.publicKey);

    // Sample payroll data
    const payrollData: PayrollData = {
        employeeAddress: "0x1234567890123456789012345678901234567890",
        amount: "5000.00",
        period: "2024-01"
    };

    // Encrypt (business side)
    const encrypted = encryptMessageEcdh(
        employeeKeys.publicKey,
        businessKeys.privateKey,
        JSON.stringify(payrollData)
    );

    console.log("Encrypted Message:", encrypted);

    // Decrypt (employee side)
    const decrypted = decryptMessageEcdh(
        businessKeys.publicKey,
        employeeKeys.privateKey,
        encrypted
    );

    console.log("Decrypted Data:", JSON.parse(decrypted));
}

// Run example if this file is executed directly
if (require.main === module) {
    exampleUsage().catch(console.error);
} 