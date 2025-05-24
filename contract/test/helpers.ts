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

const execAsync = util.promisify(exec);

/**
 * Function for deploying verifier contracts for eERC
 * @param signer Hardhat signer for the deployment
 * @param isProd Boolean for prod or dev deployments
 * @returns registrationVerifier - Registration verifier contract address
 * @returns mintVerifier - Mint verifier contract address
 * @returns withdrawVerifier - Withdraw verifier contract address
 * @returns transferVerifier - Transfer verifier contract address
 */
export const deployVerifiers = async (
  signer: SignerWithAddress,
  isProd: boolean,
) => {
  if (isProd) {
    const registrationVerifierFactory = new RegistrationVerifier__factory(
      signer,
    );
    const registrationVerifier = await registrationVerifierFactory.deploy();
    await registrationVerifier.waitForDeployment();

    const mintVerifierFactory = new MintVerifier__factory(signer);
    const mintVerifier = await mintVerifierFactory.deploy();
    await mintVerifier.waitForDeployment();

    const withdrawVerifierFactory = new WithdrawVerifier__factory(signer);
    const withdrawVerifier = await withdrawVerifierFactory.deploy();
    await withdrawVerifier.waitForDeployment();

    const transferVerifierFactory = new TransferVerifier__factory(signer);
    const transferVerifier = await transferVerifierFactory.deploy();
    await transferVerifier.waitForDeployment();

    const batchTransferVerifierFactory = new Groth16Verifier__factory(signer);
    const batchTransferVerifier = await batchTransferVerifierFactory.deploy();
    await batchTransferVerifier.waitForDeployment();

    return {
      registrationVerifier: registrationVerifier.target.toString(),
      mintVerifier: mintVerifier.target.toString(),
      withdrawVerifier: withdrawVerifier.target.toString(),
      transferVerifier: transferVerifier.target.toString(),
      batchTransferVerifier: batchTransferVerifier.target.toString(),
    };
  } if (!isProd) {
    const registrationVerifierFactory =
      new RegistrationCircuitGroth16Verifier__factory(signer);
    const registrationVerifier = await registrationVerifierFactory.deploy();
    await registrationVerifier.waitForDeployment();

    const mintVerifierFactory = new MintCircuitGroth16Verifier__factory(signer);
    const mintVerifier = await mintVerifierFactory.deploy();
    await mintVerifier.waitForDeployment();

    const withdrawVerifierFactory = new WithdrawCircuitGroth16Verifier__factory(
      signer,
    );
    const withdrawVerifier = await withdrawVerifierFactory.deploy();
    await withdrawVerifier.waitForDeployment();

    const transferVerifierFactory = new TransferCircuitGroth16Verifier__factory(
      signer,
    );
    const transferVerifier = await transferVerifierFactory.deploy();
    await transferVerifier.waitForDeployment();

    const batchTransferFactory = new Groth16Verifier__factory(signer);
    const batchTransferVerifier = await batchTransferFactory.deploy();
    await batchTransferVerifier.waitForDeployment();

    return {
      registrationVerifier: registrationVerifier.target.toString(),
      mintVerifier: mintVerifier.target.toString(),
      withdrawVerifier: withdrawVerifier.target.toString(),
      transferVerifier: transferVerifier.target.toString(),
      batchTransferVerifier: batchTransferVerifier.target.toString(),
    };
  }
  throw new Error("Invalid deployment type");
};

/**
 * Function for deploying BabyJubJub library
 * @param signer Hardhat signer for the deployment
 * @returns Deployed BabyJubJub library address
 */
export const deployLibrary = async (signer: SignerWithAddress) => {
  const babyJubJubFactory = new BabyJubJub__factory(signer);
  const babyJubJub = await babyJubJubFactory.deploy();
  await babyJubJub.waitForDeployment();

  return babyJubJub.target.toString();
};

/**
 * Function for minting tokens privately to another user
 * @param amount Amount to be
 * @param receiverPublicKey Receiver's public key
 * @param auditorPublicKey Auditor's public key
 * @returns {proof: string[], publicInputs: string[]} Proof and public inputs for the generated proof
 */
export const privateMint = async (
  amount: bigint,
  receiverPublicKey: bigint[],
  auditorPublicKey: bigint[],
): Promise<CalldataMintCircuitGroth16> => {
  // 0. get chain id
  const network = await ethers.provider.getNetwork();
  const chainId = network.chainId;

  // 1. encrypt mint amount with el-gamal
  const { cipher: encryptedAmount, random: encryptedAmountRandom } =
    encryptMessage(receiverPublicKey, amount);

  // 2. create pct for the receiver with the mint amount
  const {
    ciphertext: receiverCiphertext,
    nonce: receiverNonce,
    encRandom: receiverEncRandom,
    authKey: receiverAuthKey,
  } = processPoseidonEncryption([amount], receiverPublicKey);

  // 3. create pct for the auditor with the mint amount
  const {
    ciphertext: auditorCiphertext,
    nonce: auditorNonce,
    encRandom: auditorEncRandom,
    authKey: auditorAuthKey,
  } = processPoseidonEncryption([amount], auditorPublicKey);

  // 4. create nullifier hash for the auditor
  const nullifierHash = poseidon([chainId, ...auditorCiphertext]);

  const input = {
    ValueToMint: amount,
    ChainID: chainId,
    NullifierHash: nullifierHash,
    ReceiverPublicKey: receiverPublicKey,
    ReceiverVTTC1: encryptedAmount[0],
    ReceiverVTTC2: encryptedAmount[1],
    ReceiverVTTRandom: encryptedAmountRandom,
    ReceiverPCT: receiverCiphertext,
    ReceiverPCTAuthKey: receiverAuthKey,
    ReceiverPCTNonce: receiverNonce,
    ReceiverPCTRandom: receiverEncRandom,
    AuditorPublicKey: auditorPublicKey,
    AuditorPCT: auditorCiphertext,
    AuditorPCTAuthKey: auditorAuthKey,
    AuditorPCTNonce: auditorNonce,
    AuditorPCTRandom: auditorEncRandom,
  };

  const circuit = await zkit.getCircuit("MintCircuit");
  const mintCircuit = circuit as unknown as MintCircuit;

  const proof = await mintCircuit.generateProof(input);
  const calldata = await mintCircuit.generateCalldata(proof);

  return calldata;
};

/**
 * Function for burning tokens privately
 * Private burn is transferring the encrypted amount to BURN_USER which is the identity point (0, 1)
 * @param user
 * @param userBalance User balance in plain
 * @param amount  Amount to be burned
 * @param userEncryptedBalance User encrypted balance from eERC contract
 * @param auditorPublicKey Auditor's public key
 * @returns
 */
export const privateBurn = async (
  user: User,
  userBalance: bigint,
  amount: bigint,
  userEncryptedBalance: bigint[],
  auditorPublicKey: bigint[],
) => {
  return privateTransfer(
    user,
    userBalance,
    [0n, 1n],
    amount,
    userEncryptedBalance,
    auditorPublicKey,
  );
};

/**
 * Function for transferring tokens privately in the eERC protocol
 * @param sender Sender
 * @param senderBalance Sender balance in plain
 * @param receiverPublicKey Receiver's public key
 * @param transferAmount Amount to be transferred
 * @param senderEncryptedBalance Sender encrypted balance from eERC contract
 * @param auditorPublicKey Auditor's public key
 * @returns proof, publicInputs - Proof and public inputs for the generated proof
 * @returns senderBalancePCT - Sender's balance after the transfer encrypted with Poseidon encryption
 */
export const privateTransfer = async (
  sender: User,
  senderBalance: bigint,
  receiverPublicKey: bigint[],
  transferAmount: bigint,
  senderEncryptedBalance: bigint[],
  auditorPublicKey: bigint[],
): Promise<{
  proof: CalldataTransferCircuitGroth16;
  senderBalancePCT: bigint[];
}> => {
  const senderNewBalance = senderBalance - transferAmount;
  // 1. encrypt the transfer amount with el-gamal for sender
  const { cipher: encryptedAmountSender, random: encryptedAmountSenderRandom } =
    encryptMessage(sender.publicKey, transferAmount);

  // 2. encrypt the transfer amount with el-gamal for receiver
  const {
    cipher: encryptedAmountReceiver,
    random: encryptedAmountReceiverRandom,
  } = encryptMessage(receiverPublicKey, transferAmount);

  // 3. creates a pct for receiver with the transfer amount
  const {
    ciphertext: receiverCiphertext,
    nonce: receiverNonce,
    authKey: receiverAuthKey,
    encRandom: receiverEncRandom,
  } = processPoseidonEncryption([transferAmount], receiverPublicKey);

  // 4. creates a pct for auditor with the transfer amount
  const {
    ciphertext: auditorCiphertext,
    nonce: auditorNonce,
    authKey: auditorAuthKey,
    encRandom: auditorEncRandom,
  } = processPoseidonEncryption([transferAmount], auditorPublicKey);

  // 5. create pct for the sender with the newly calculated balance
  const {
    ciphertext: senderCiphertext,
    nonce: senderNonce,
    authKey: senderAuthKey,
  } = processPoseidonEncryption([senderNewBalance], sender.publicKey);

  const circuit = await zkit.getCircuit("TransferCircuit");
  const transferCircuit = circuit as unknown as TransferCircuit;

  const input = {
    ValueToTransfer: transferAmount,
    SenderPrivateKey: sender.formattedPrivateKey,
    SenderPublicKey: sender.publicKey,
    SenderBalance: senderBalance,
    SenderBalanceC1: senderEncryptedBalance.slice(0, 2),
    SenderBalanceC2: senderEncryptedBalance.slice(2, 4),
    SenderVTTC1: encryptedAmountSender[0],
    SenderVTTC2: encryptedAmountSender[1],
    ReceiverPublicKey: receiverPublicKey,
    ReceiverVTTC1: encryptedAmountReceiver[0],
    ReceiverVTTC2: encryptedAmountReceiver[1],
    ReceiverVTTRandom: encryptedAmountReceiverRandom,
    ReceiverPCT: receiverCiphertext,
    ReceiverPCTAuthKey: receiverAuthKey,
    ReceiverPCTNonce: receiverNonce,
    ReceiverPCTRandom: receiverEncRandom,

    AuditorPublicKey: auditorPublicKey,
    AuditorPCT: auditorCiphertext,
    AuditorPCTAuthKey: auditorAuthKey,
    AuditorPCTNonce: auditorNonce,
    AuditorPCTRandom: auditorEncRandom,
  };

  const proof = await transferCircuit.generateProof(input);
  const calldata = await transferCircuit.generateCalldata(proof);

  return {
    proof: calldata,
    senderBalancePCT: [...senderCiphertext, ...senderAuthKey, senderNonce],
  };
};

/**
 * Function for decrypting a PCT
 * @param privateKey
 * @param pct PCT to be decrypted
 * @param length Length of the original input array
 * @returns decrypted - Decrypted message as an array
 */
export const decryptPCT = async (
  privateKey: bigint,
  pct: bigint[],
  length = 1,
) => {
  // extract the ciphertext, authKey, and nonce from the pct
  const ciphertext = pct.slice(0, 4);
  const authKey = pct.slice(4, 6);
  const nonce = pct[6];

  const decrypted = processPoseidonDecryption(
    ciphertext,
    authKey,
    nonce,
    privateKey,
    length,
  );

  return decrypted;
};

/**
 * Function for withdrawing tokens privately in the eERC protocol
 * @param amount Amount to be withdrawn
 * @param user
 * @param userEncryptedBalance User encrypted balance from eERC contract
 * @param userBalance User plain balance
 * @param auditorPublicKey Auditor's public key
 * @returns proof - Proof and public inputs for the generated proof
 * @returns userBalancePCT - User's balance after the withdrawal encrypted with Poseidon encryption
 */
export const withdraw = async (
  amount: bigint,
  user: User,
  userEncryptedBalance: bigint[],
  userBalance: bigint,
  auditorPublicKey: bigint[],
): Promise<{
  proof: CalldataWithdrawCircuitGroth16;
  userBalancePCT: bigint[];
}> => {
  const newBalance = userBalance - amount;
  const userPublicKey = user.publicKey;

  // 1. create pct for the user with the newly calculated balance
  const {
    ciphertext: userCiphertext,
    nonce: userNonce,
    authKey: userAuthKey,
  } = processPoseidonEncryption([newBalance], userPublicKey);

  // 2. create pct for the auditor with the withdrawal amount
  const {
    ciphertext: auditorCiphertext,
    nonce: auditorNonce,
    encRandom: auditorEncRandom,
    authKey: auditorAuthKey,
  } = processPoseidonEncryption([amount], auditorPublicKey);

  const input = {
    ValueToWithdraw: amount,
    SenderPrivateKey: user.formattedPrivateKey,
    SenderPublicKey: userPublicKey,
    SenderBalance: userBalance,
    SenderBalanceC1: userEncryptedBalance.slice(0, 2),
    SenderBalanceC2: userEncryptedBalance.slice(2, 4),
    AuditorPublicKey: auditorPublicKey,
    AuditorPCT: auditorCiphertext,
    AuditorPCTAuthKey: auditorAuthKey,
    AuditorPCTNonce: auditorNonce,
    AuditorPCTRandom: auditorEncRandom,
  };

  const circuit = await zkit.getCircuit("WithdrawCircuit");
  const withdrawCircuit = circuit as unknown as WithdrawCircuit;

  const proof = await withdrawCircuit.generateProof(input);
  const calldata = await withdrawCircuit.generateCalldata(proof);

  return {
    proof: calldata,
    userBalancePCT: [...userCiphertext, ...userAuthKey, userNonce],
  };
};

/**
 * Function for getting the decrypted balance of a user by decrypting amount and balance PCTs
 * and comparing it with the decrypted balance from the eERC contract
 * @param privateKey
 * @param amountPCTs User amount PCTs
 * @param balancePCT User balance PCT
 * @param encryptedBalance User encrypted balance from eERC contract
 * @returns totalBalance - balance of the user
 */
export const getDecryptedBalance = async (
  privateKey: bigint,
  amountPCTs: AmountPCTStructOutput[],
  balancePCT: bigint[],
  encryptedBalance: bigint[][],
) => {
  let totalBalance = 0n;

  // decrypt the balance PCT
  if (balancePCT.some((e) => e !== 0n)) {
    const decryptedBalancePCT = await decryptPCT(privateKey, balancePCT);
    totalBalance += BigInt(decryptedBalancePCT[0]);
  }

  // decrypt all the amount PCTs and add them to the total balance
  for (const [pct] of amountPCTs) {
    if (pct.some((e) => e !== 0n)) {
      const decryptedAmountPCT = await decryptPCT(privateKey, pct);
      totalBalance += BigInt(decryptedAmountPCT[0]);
    }
  }

  // decrypt the balance from the eERC contract
  const decryptedBalance = decryptPoint(
    privateKey,
    encryptedBalance[0],
    encryptedBalance[1],
  );

  // compare the decrypted balance with the calculated balance
  if (totalBalance !== 0n) {
    const expectedPoint = mulPointEscalar(Base8, totalBalance);
    expect(decryptedBalance).to.deep.equal(expectedPoint);
  }

  return totalBalance;
};


/**
 * Function for generating the proof and calldata for a batch transfer
 * @param users Users to be transferred to
 * @param amounts Amounts to be transferred
 * @param sender Sender
 * @param senderBalance Sender balance
 * @param auditorPublicKey Auditor's public key
 * @returns proof - Proof and public inputs for the generated proof
 * @returns senderBalancePCT - Sender's balance after the transfer encrypted with Poseidon encryption
 */
export const batchTransfer = async (
  sender: User,
  senderBalance: bigint,
  recipients: User[],
  amounts:bigint[],
  senderEncryptedBalance: bigint[],
  auditorPublicKey: bigint[],
): Promise <{
  proof: CalldataBatchTransferCircuitGroth16, // set the data type that will be returned
  senderBalancePCT: bigint[]
}> => { 
  const totalAmount = amounts.reduce((a, b) => a + b, 0n);
  console.log("Total Amount:", totalAmount);
  const senderNewBalance = senderBalance - totalAmount;

  // 1. Encrypt transfer amount for sender (same as privateTransfer)
  const { cipher: encryptedAmountSender, random: encryptedAmountSenderRandom } =
    encryptMessage(sender.publicKey, totalAmount);

  // 2. generate encrypted amounts for each receiver
  const receiverEncryptions = await Promise.all(
    recipients.map(async (receiver, i) => {
      const { cipher, random } = encryptMessage(receiver.publicKey, amounts[i]);
      return { cipher, random };
    })
  );

  // 3. generate the receiver PCTs
  const receiverPCTs = await Promise.all(
    recipients.map(async (receiver, i) => {
      const {
        ciphertext: receiverCipherText,
        nonce: receiverNonce,
        authKey: receiverAuthKey,
        encRandom: receiverEncRandom,
      } = processPoseidonEncryption([amounts[i]], receiver.publicKey);

      console.log(`\nReceiver ${i} PCT Construction Details:`);
      console.log("Input amount:", amounts[i].toString());
      console.log("Public key:", receiver.publicKey.map(k => k.toString()));
      console.log("Ciphertext (raw):", receiverCipherText.map(c => c.toString()));
      console.log("Auth key (raw):", receiverAuthKey.map(k => k.toString()));
      console.log("Nonce (raw):", receiverNonce.toString());
      console.log("Random (raw):", receiverEncRandom.toString());

      return {
        pct: receiverCipherText,
        nonce: receiverNonce,
        random: receiverEncRandom,
        authKey: receiverAuthKey      
      };
    })
  );

  // 4. generate the auditor PCT 
  const {
    ciphertext: auditorPCT,
    nonce: auditorNonce,
    encRandom: auditorEncRandom,
    authKey: auditorAuthKey
  } = processPoseidonEncryption([totalAmount], auditorPublicKey);

  console.log("\nAuditor PCT Construction Details:");
  console.log("Input total amount:", totalAmount.toString());
  console.log("Public key:", auditorPublicKey.map(k => k.toString()));
  console.log("Ciphertext (raw):", auditorPCT.map(c => c.toString()));
  console.log("Auth key (raw):", auditorAuthKey.map(k => k.toString()));
  console.log("Nonce (raw):", auditorNonce.toString());
  console.log("Random (raw):", auditorEncRandom.toString());

  // 5. Generate the sender PCT
  const {
    ciphertext: senderPCT,
    nonce: senderNonce,
    encRandom: senderEncRandom,
    authKey: senderAuthKey
  } = processPoseidonEncryption([senderNewBalance], sender.publicKey);

  console.log("\nSender PCT Construction Details:");
  console.log("Input new balance:", senderNewBalance.toString());
  console.log("Public key:", sender.publicKey.map(k => k.toString()));
  console.log("Ciphertext (raw):", senderPCT.map(c => c.toString()));
  console.log("Auth key (raw):", senderAuthKey.map(k => k.toString()));
  console.log("Nonce (raw):", senderNonce.toString());
  console.log("Random (raw):", senderEncRandom.toString());
  
  // 6. Prepare the circuit inputs
  const input = {
    ValueToTransfer: totalAmount,

    SenderPrivateKey: sender.formattedPrivateKey,
    SenderPublicKey: sender.publicKey,
    SenderBalance: senderBalance, // unencrypted balance
    SenderBalanceC1: senderEncryptedBalance.slice(0, 2),
    SenderBalanceC2: senderEncryptedBalance.slice(2, 4),

    SenderVTTC1: encryptedAmountSender[0],
    SenderVTTC2: encryptedAmountSender[1],
    //SenderVTTRandom: encrypatedAmountSenderRandom,

    ReceiverPublicKey: recipients.map((r) => r.publicKey),
    ReceiverVTTC1: receiverEncryptions.map((r) => r.cipher[0]),
    ReceiverVTTC2: receiverEncryptions.map((r) => r.cipher[1]),
    ReceiverVTTRandom: receiverEncryptions.map((r) => r.random),

    ReceiverPCT: receiverPCTs.map((r) => r.pct),
    ReceiverPCTAuthKey: receiverPCTs.map((r) => r.authKey),
    ReceiverPCTNonce: receiverPCTs.map((r) => r.nonce),
    ReceiverPCTRandom: receiverPCTs.map((r) => r.random),

    AuditorPublicKey: auditorPublicKey,
    AuditorPCT: auditorPCT,
    AuditorPCTAuthKey: auditorAuthKey,
    AuditorPCTNonce: auditorNonce,
    AuditorPCTRandom: auditorEncRandom,

    ReceiverAmount: amounts
  };

  // 7. Generate the proof and calldata
  const circuit = await zkit.getCircuit("BatchTransferCircuit");
  const batchTransferCircuit = circuit as unknown as BatchTransferCircuit;

  const proof = await batchTransferCircuit.generateProof(input);
  const calldata = await batchTransferCircuit.generateCalldata(proof);

  return { proof:calldata, senderBalancePCT: [...senderPCT, ...senderAuthKey, senderNonce] };
}