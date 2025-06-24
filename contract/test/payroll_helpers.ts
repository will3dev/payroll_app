import { exec } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import util from "node:util";
import type { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/dist/src/signer-with-address";
import { Base8, mulPointEscalar, subOrder } from "@zk-kit/baby-jubjub";
import { expect } from "chai";
import { ethers, zkit } from "hardhat";
import { poseidon } from "maci-crypto/build/ts/hashing";
import { formatPrivKeyForBabyJub } from "maci-crypto";
import type {
  CalldataMintCircuitGroth16,
  CalldataTransferCircuitGroth16,
  CalldataWithdrawCircuitGroth16,
  CalldataBatchTransferCircuitGroth16,
  CalldataEmployeeDataGroth16,
  EmployeeData,
  MintCircuit,
  TransferCircuit,
  WithdrawCircuit,
  BatchTransferCircuit,
} from "../generated-types/zkit";
import { 
  processPoseidonDecryption, 
  processPoseidonEncryption, 
  processPoseidonEncryptionEcdh, 
  processPoseidonDecryptionEcdhSender, 
  processPoseidonDecryptionEcdh,
  generateSharedKey,
  generateEncRandomFromKnownMultiplier,
  processPoseidonEncryptionWithEncRandom,
  stringToBigInt,
  randomNonce
} from "../src";
import { decryptPoint, encryptMessage } from "../src/jub/jub";
import type { AmountPCTStructOutput } from "../typechain-types/contracts/EncryptedERC";
import { BabyJubJub__factory } from "../typechain-types/factories/contracts/libraries";
import {
  MintCircuitGroth16Verifier__factory,
  RegistrationCircuitGroth16Verifier__factory,
  TransferCircuitGroth16Verifier__factory,
  WithdrawCircuitGroth16Verifier__factory,
  BatchTransferCircuitGroth16Verifier__factory,
  EmployeeDataGroth16Verifier__factory,
} from "../typechain-types/factories/contracts/verifiers";

import {
  MintVerifier__factory,
  RegistrationVerifier__factory,
  TransferVerifier__factory,
  WithdrawVerifier__factory,
  
} from "../typechain-types/factories/contracts/prod";
import {
  Groth16Verifier__factory
} from "../typechain-types/factories/contracts/prod/BatchTransferVerifier2.sol"

import type { User } from "./user";
import { validateBatchTransferInputs, BatchTransferInputs } from "../scripts/validate-circuit-inputs";

const execAsync = util.promisify(exec);

export const generateJubKeysFromPrivateKey = async (
  privateKey: bigint
): Promise <{
  publicKey: bigint[],
  formattedPrivateKey: bigint
}> => {
  const formattedPrivateKey = formatPrivKeyForBabyJub(privateKey) % subOrder;
  const publicKey = mulPointEscalar(Base8, formattedPrivateKey).map((x) => BigInt(x));
  return { publicKey, formattedPrivateKey }
}


/**
 * This is used to generate the encrypted bonus ID PCT for a bonus that is has already been created.
 * This will be used by the employee during the claim process.
 * It will be required to ensure that the right ZKP is being used for the claim.
 * @param bonusId 
 * @param privateKey 
 * @param publicKey 
 * @param lastBonusBlockTimestamp 
 * @param nonce 
 * @returns 
 */

export const generateEncryptedBonusIdPCTForClaim = async (
  bonusId: bigint,
  privateKey: bigint,
  publicKey: bigint[],
  lastBonusBlockTimestamp: bigint,
  nonce: bigint
): Promise<{
  ciphertext: bigint[],
  authKey: bigint[],
  nonce:bigint,
  encRandom: bigint,
  poseidonEncryptionKey: bigint[]
}> => {
  
  const encRandom = generateEncRandomFromKnownMultiplier(lastBonusBlockTimestamp, privateKey);

  const {
    ciphertext: bonusIdPCT,
    authKey: bonusIdPCTAuthKey,
    nonce: bonusIdNonce,
    encRandom: bonusIdEncRandom,
    poseidonEncryptionKey: bonusIdPCTEncKey
  } = await processPoseidonEncryptionWithEncRandom([bonusId], publicKey, encRandom, nonce);


  return {
    ciphertext: bonusIdPCT,
    authKey: bonusIdPCTAuthKey,
    nonce: bonusIdNonce,
    encRandom: bonusIdEncRandom,
    poseidonEncryptionKey: bonusIdPCTEncKey
  }
}



/**
 * This is used to generate the bonus ID PCT for a new bonus.
 * This ensures that there is a known encRandom value being used so that the 
 * employee can generate the same PCT with the provided bonus private key during the process
 * of claiming the bonus in the ZKP.
 * @param bonusId 
 * @param privateKey 
 * @param publicKey 
 * @param lastBonusBlockTimestamp 
 * @returns 
 */
export const generateBonusIdPCTForNewBonus = async (
  bonusId: bigint,
  privateKey: bigint,
  publicKey: bigint[],
  lastBonusBlockTimestamp: bigint
): Promise<{
  ciphertext: bigint[],
  authKey: bigint[],
  nonce: bigint,
  encRandom: bigint,
  poseidonEncryptionKey: bigint[]
}> => {
  const encRandom = generateEncRandomFromKnownMultiplier(lastBonusBlockTimestamp, privateKey);
  const nonce = randomNonce();

  const {
    ciphertext: bonusIdPCT,
    authKey: bonusIdPCTAuthKey,
    encRandom: bonusIdEncRandom,
    poseidonEncryptionKey: bonusIdPCTEncKey,
    nonce: bonusIdNonce
  } = await processPoseidonEncryptionWithEncRandom([bonusId], publicKey, encRandom, nonce);

  return {
    ciphertext: bonusIdPCT,
    authKey: bonusIdPCTAuthKey,
    nonce: bonusIdNonce,
    encRandom: bonusIdEncRandom,
    poseidonEncryptionKey: bonusIdPCTEncKey
  }
}


/**
 * Analyzes any circuit output to determine the order of public signals
 * @param circuitInput The input object used to generate the proof
 * @param publicSignals The public signals output from the circuit
 * @returns An object containing field order array and mapping object
 */
export const analyzeCircuitOutput = (
  circuitInput: Record<string, any>,
  publicSignals: (string | bigint)[]
): {
  fieldOrder: string[];
  fieldMapping: Record<string, number>;
} => {
  const fieldOrder: string[] = [];
  const usedIndices = new Set<number>();

  // Convert all signals to bigints for comparison
  const signalsAsBigInts = publicSignals.map(signal => BigInt(signal));

  // For each public signal, find which input field it matches
  for (let i = 0; i < signalsAsBigInts.length; i++) {
    const signalValue = signalsAsBigInts[i];
    let foundMatch = false;

    // Check each input field for a match
    for (const [fieldName, fieldValue] of Object.entries(circuitInput)) {
      // Handle different types of field values
      if (typeof fieldValue === 'bigint' && fieldValue === signalValue) {
        if (!usedIndices.has(i)) {
          fieldOrder[i] = fieldName;
          usedIndices.add(i);
          foundMatch = true;
          break;
        }
      } else if (Array.isArray(fieldValue)) {
        // Handle array fields (like public keys)
        for (let j = 0; j < fieldValue.length; j++) {
          if (typeof fieldValue[j] === 'bigint' && fieldValue[j] === signalValue) {
            if (!usedIndices.has(i)) {
              fieldOrder[i] = `${fieldName}[${j}]`;
              usedIndices.add(i);
              foundMatch = true;
              break;
            }
          }
        }
        if (foundMatch) break;
      }
    }

    // If no match found, mark as unknown
    if (!foundMatch) {
      fieldOrder[i] = `unknown_${i}`;
    }
  }

  // Create mapping object
  const fieldMapping: Record<string, number> = {};
  fieldOrder.forEach((fieldName, index) => {
    fieldMapping[fieldName] = index;
  });

  return { fieldOrder, fieldMapping };
};

export const claimBonus = async (
  employee: User,
  businessPublicKey: bigint[],
  employeeBonusId: bigint,
  employeeId: bigint,
  employeeName: string,
  employeeBonusPrivateKey: bigint,
  bonusPCTData: bigint[],
  bonusNonce: bigint,
): Promise<{
  proof: CalldataEmployeeDataGroth16,
  inputValues: Record<string, any>
}> => {

  // generate the shared public key
  const sharedKey = generateSharedKey(businessPublicKey, employee.formattedPrivateKey);

 // generate the bonus public key from the bonus private key
  const { 
    publicKey: bonusPubKey,
    formattedPrivateKey: bonusFormattedPrivateKey
  } = await generateJubKeysFromPrivateKey(employeeBonusPrivateKey);

  // generate the bonus ID PCT using the bonus public key and known values.
  // This BonusID PCT should match the one stored on the contract.
  const {
    ciphertext: bonusIdPCT,
    authKey: bonusIdPCTAuthKey,
    nonce: bonusIdNonce,
    encRandom: bonusIdEncRandom,
    poseidonEncryptionKey: _
  } = await generateEncryptedBonusIdPCTForClaim(
    employeeBonusId,
    bonusFormattedPrivateKey,
    bonusPubKey,
    bonusNonce,
    bonusPCTData[6]
  )


  // generate the employee ID PCT using the employee public key
  const {
    ciphertext: employeeIdPCT,
    authKey: employeeIdPCTAuthKey,
    nonce: employeeIdNonce,
    encRandom: employeeIdEncRandom
  } = await processPoseidonEncryption(
    [employeeId],
    employee.publicKey
  );

  // generate the employee name PCT using the shared public key
  const {
    ciphertext: employeeNamePCT,
    authKey: employeeNamePCTAuthKey,
    nonce: employeeNameNonce,
    poseidonEncryptionKey: employeeNamePCTEncKey
  } = await processPoseidonEncryptionEcdh(
    businessPublicKey,
    employee.privateKey,
    employeeName
  );

  // generate the employeeData proof
  const circuit = await zkit.getCircuit("EmployeeData");
  const employeeDataCircuit = circuit as unknown as EmployeeData;

  const employeeNameBigInt = stringToBigInt(employeeName);

  const input = {
    EmployeeId: employeeId,
    EmployeeName: employeeNameBigInt,
    EmployeeBonusId: employeeBonusId,
    EmployerPublicKey: businessPublicKey,
    SharedKey: sharedKey,
    EmployeePrivateKey: employee.formattedPrivateKey,
    EmployeePublicKey: employee.publicKey,
    EmployeeBonusPrivateKey: bonusFormattedPrivateKey,
    EmployeeBonusPublicKey: bonusPubKey,
    EmployeeIdPCT: employeeIdPCT,
    EmployeeIdPCTAuthKey: employeeIdPCTAuthKey,
    EmployeeIdPCTNonce: employeeIdNonce,
    EmployeeIdPCTRandom: employeeIdEncRandom,
    BonusIdPCT: bonusIdPCT,
    BonusIdPCTAuthKey: bonusIdPCTAuthKey,
    BonusIdPCTNonce: bonusIdNonce,
    BonusIdPCTRandom: bonusIdEncRandom,
    EmployeeNamePCT: employeeNamePCT,
    EmployeeNamePCTNonce: employeeNameNonce,
  }

  const proof = await employeeDataCircuit.generateProof(input);
  const calldata = await employeeDataCircuit.generateCalldata(proof);

  return {
    proof: calldata,
    inputValues: input
  }
}