import { exec } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import util from "node:util";
import assert from "node:assert";
import type { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/dist/src/signer-with-address";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";
import { expect } from "chai";
import { ethers, zkit } from "hardhat";
import { poseidon } from "maci-crypto/build/ts/hashing";
import type {
  CalldataMintCircuitGroth16,
  CalldataTransferCircuitGroth16,
  CalldataWithdrawCircuitGroth16,
  CalldataBatchTransferCircuitGroth16,
  MintCircuit,
  TransferCircuit,
  WithdrawCircuit,
  BatchTransferCircuit,
  VaultWithdrawalCircuit,
  CalldataVaultWithdrawalCircuitGroth16
} from "../generated-types/zkit";
import { processPoseidonDecryption, processPoseidonEncryption } from "../src";
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
import {
  processPoseidonEncryptionEcdh,
  processPoseidonDecryptionEcdh,
  processPoseidonDecryptionEcdhSender,
  generateSharedKey
} from "../src/poseidon/poseidon";

import type { User } from "./user";
import { validateBatchTransferInputs, BatchTransferInputs } from "../scripts/validate-circuit-inputs";



export const calculateMaxDraw = async (
    startBlock: bigint,
    currentBlock: bigint,
    blocksPerEpoch: bigint,
    distributionAmount: bigint, 
    totalWithdraws: bigint,
): Promise<{ 
  availableToDraw: bigint,
  remainder: bigint,
  epochsSinceStart: bigint
}> => {

    const diff = currentBlock - startBlock;
    const epochsSinceStart = diff / blocksPerEpoch;
    const remainder = diff % blocksPerEpoch;
    
    const totalPossibleDrawAmount = epochsSinceStart * distributionAmount;
    const availableToDraw = totalPossibleDrawAmount - totalWithdraws;


    return {
      availableToDraw: availableToDraw,
      remainder: remainder,
      epochsSinceStart: epochsSinceStart
    }
}


export const vaultWithdrawal = async (
  receiver: User,
  funder: User,
  tokenId: bigint,
  withdrawalAmount: bigint,
  totalWithdraw: bigint,
  totalWithdrawEGCT: bigint[],
  vaultBalance: bigint,
  vaultBalanceEGCT: bigint[],
  auditorPublicKey: bigint[],
  distributionAmount: bigint,
  distributionAmountPCT: bigint[],
  distributionAmountNonce: bigint,
  epochLength: bigint,
  startBlock: bigint,
  currentBlock: bigint,
  epochsSinceStart: bigint,
  remainder: bigint
): Promise <{
  proof: CalldataVaultWithdrawalCircuitGroth16,
  senderBalancePCT: bigint[]
}> => {
  // 1. calculate the balance after the withdrawal
  const newVaultBalance = vaultBalance - withdrawalAmount;

  console.log("Expected vault balance", newVaultBalance);

  // 2. Generate vault balance PCT after the withdrawal
  const {
    ciphertext: vaultBalanceCiphertext,
    nonce: vaultBalanceNonce,
    authKey: vaultBalanceAuthKey,
    encRandom: vaultBalanceEncRandom
  } = processPoseidonEncryption([newVaultBalance], receiver.publicKey)


  // 3. Calculate the new total withdrawal amount
  const newTotalWithdraws = totalWithdraw + withdrawalAmount;

  // 4. Encrypt the new total withdrawal amount with poseidon encryption
  const {
    ciphertext: newTotalWithdrawsCiphertext,
    nonce: newTotalWithdrawsNonce,
    authKey: newTotalWithdrawsAuthKey,
    encRandom: newTotalWithdrawsEncRandom
  } = processPoseidonEncryption([newTotalWithdraws], receiver.publicKey);
  
  // 5. Encrypt the withdrawal amoutn with auditor public key with poseidon encryption
  const {
    ciphertext: auditorCiphertext,
    nonce: auditorNonce,
    authKey: auditorAuthKey,
    encRandom: auditorEncRandom
  } = processPoseidonEncryption([withdrawalAmount], auditorPublicKey);

  // 6. Encrypt the distribution amount with poseidon and el-gamalencryption for the "receiver"
  const {
    ciphertext: receiverCiphertext,
    encRandom: receiverEncRandom,
    nonce: receiverNonce,
    authKey: receiverAuthKey
  } = processPoseidonEncryption([withdrawalAmount], receiver.publicKey);

  const {
    cipher: encryptedWithdrawalAmount,
    random: encryptedWithdrawalAmountRandom
  } = encryptMessage(receiver.publicKey, withdrawalAmount);
  
  // 7. Check that the withdrawal amount is less than the max allowed withdrawal amount, get the remainder value
  // TO DO: Move this out of this function and just take remainder as an input
  const {
    availableToDraw
  } = await calculateMaxDraw(startBlock, currentBlock, epochLength, distributionAmount, totalWithdraw);

  assert(withdrawalAmount <= availableToDraw, "Withdrawal amount is greater than the available to draw");

  
  // 8. Generate the shared key
  const sharedKey = generateSharedKey(funder.publicKey, receiver.formattedPrivateKey);
  
  // 8. generate the proof

  const input = {
    withdrawalAmount: withdrawalAmount,
    senderPrivateKey: receiver.formattedPrivateKey,
    senderPublicKey: receiver.publicKey,
    vaultBalance: vaultBalance,
    vaultBalanceC1: vaultBalanceEGCT.slice(0,2),
    vaultBalanceC2: vaultBalanceEGCT.slice(2,4),
    funderPublicKey: funder.publicKey,
    withdrawalAmountC1: encryptedWithdrawalAmount[0],
    withdrawalAmountC2: encryptedWithdrawalAmount[1],
    withdrawalAmountPCT: receiverCiphertext,
    withdrawalAmountAuthKey: receiverAuthKey,
    withdrawalAmountNonce: receiverNonce,
    withdrawalAmountRandom: receiverEncRandom,
    totalWithdraw: totalWithdraw,
    totalWithdrawC1: totalWithdrawEGCT.slice(0,2),
    totalWithdrawC2: totalWithdrawEGCT.slice(2,4),
    newTotalWithdraws: newTotalWithdraws,
    newTotalWithdrawsPCT: newTotalWithdrawsCiphertext,
    newTotalWithdrawsAuthKey: newTotalWithdrawsAuthKey,
    newTotalWithdrawsNonce: newTotalWithdrawsNonce,
    newTotalWithdrawsRandom: newTotalWithdrawsEncRandom,
    AuditorPublicKey: auditorPublicKey,
    AuditorPCT: auditorCiphertext,
    AuditorPCTAuthKey: auditorAuthKey,
    AuditorPCTNonce: auditorNonce,
    AuditorPCTRandom: auditorEncRandom,
    sharedKey: sharedKey,
    epochLength: epochLength,
    startBlock: startBlock,
    currentBlock: currentBlock,
    epochsSinceStart: epochsSinceStart,
    remainder: remainder,
    distributionAmount: distributionAmount,
    distributionAmountPCT: distributionAmountPCT,
    distributionAmountNonce: distributionAmountNonce
  }

  const circuit = await zkit.getCircuit("VaultWithdrawalCircuit");
  const vaultWithdrawalCircuit = circuit as unknown as VaultWithdrawalCircuit;

  const proof = await vaultWithdrawalCircuit.generateProof(input);
  const calldata = await vaultWithdrawalCircuit.generateCalldata(proof);

  // 8. return the proof and the sender balance PCT
  return {
    proof: calldata,
    senderBalancePCT: [...vaultBalanceCiphertext, ...vaultBalanceAuthKey, vaultBalanceNonce]
  }

}