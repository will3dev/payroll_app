import { exec } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import util from "node:util";
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
  processPoseidonDecryptionEcdhSender
} from "../src/poseidon/poseidon";

import type { User } from "./user";
import { validateBatchTransferInputs, BatchTransferInputs } from "../scripts/validate-circuit-inputs";



export const calculateMaxDraw = async (
    startBlock: bigint,
    currentBlock: bigint,
    lastDrawBlock: bigint,
    blocksPerEpoch: bigint,
    distributionAmount: bigint
): Promise<bigint> => {

    const epochsSinceStart = (currentBlock - startBlock) / blocksPerEpoch;

    const epochsSinceDraw = (lastDrawBlock - startBlock) / blocksPerEpoch

    return (epochsSinceStart - epochsSinceDraw) * distributionAmount
}
