import { exec } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import util from "node:util";
import type { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/dist/src/signer-with-address";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";
import { expect } from "chai";
import { formatPrivKeyForBabyJub } from "maci-crypto";
import { decryptPoint, encryptMessage } from "../src/jub/jub";
import type { AmountPCTStructOutput } from "../typechain-types/contracts/EncryptedERC";
import { BabyJubJub__factory } from "../typechain-types/factories/contracts/libraries";
import {
  MintVerifier__factory,
  RegistrationVerifier__factory,
  TransferVerifier__factory,
  WithdrawVerifier__factory,
} from "../typechain-types/factories/contracts/verifiers";
import type { User } from "./user";
import { ethers } from "hardhat";
import { poseidon } from "maci-crypto/build/ts/hashing";
import { processPoseidonDecryption, processPoseidonEncryption } from "../src";

const execAsync = util.promisify(exec);

/**
 * Function for deploying verifier contracts for eERC
 * @param signer Hardhat signer for the deployment
 * @returns registrationVerifier - Registration verifier contract address
 * @returns mintVerifier - Mint verifier contract address
 * @returns withdrawVerifier - Withdraw verifier contract address
 * @returns transferVerifier - Transfer verifier contract address
 */
export const deployVerifiers = async (signer: SignerWithAddress) => {
  const registrationVerifierFactory = new RegistrationVerifier__factory(signer);
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

  return {
    registrationVerifier: registrationVerifier.target.toString(),
    mintVerifier: mintVerifier.target.toString(),
    withdrawVerifier: withdrawVerifier.target.toString(),
    transferVerifier: transferVerifier.target.toString(),
  };
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
 *
 * @param {PROOF_TYPE} type  Proof type
 * @param {object}     input Proof Input
 * @returns Proof
 * @dev This function generates a proof for the given input and proof type.
 * 	    It uses the binary in the outputs folder.
 */
export const generateGnarkProof = async (
  type: string,
  input: string
): Promise<string[]> => {
  const outputPath = path.join(__dirname, `${type}.output.json`);

  const pkPath = path.join(__dirname, "../", "build", `${type}.pk`);
  const csPath = path.join(__dirname, "../", "build", `${type}.r1cs`);

  const executableName = "encryptedERC";
  const executable = path.join(__dirname, "../", "zk", "build", executableName);

  const cmd = `${executable} --operation ${type} --input '${input}' --pk ${pkPath} --cs ${csPath} --output ${outputPath}`;

  // todo why stdout?
  const now = Date.now();
  console.log("Generating proof for ", type);
  const { stderr: err } = await execAsync(cmd);
  console.log("Proof generation took", Date.now() - now, "ms");
  if (err) throw new Error(err);

  const output = fs.readFileSync(outputPath, "utf-8");
  const { proof } = JSON.parse(output);

  fs.unlinkSync(outputPath);

  return proof;
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
  auditorPublicKey: bigint[]
) => {
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

  const publicInputs = [
    ...receiverPublicKey.map(String),
    ...encryptedAmount[0].map(String),
    ...encryptedAmount[1].map(String),
    ...receiverCiphertext.map(String),
    ...receiverAuthKey.map(String),
    receiverNonce.toString(),
    ...auditorPublicKey.map(String),
    ...auditorCiphertext.map(String),
    ...auditorAuthKey.map(String),
    auditorNonce.toString(),
    chainId.toString(),
    nullifierHash.toString(),
  ];

  const privateInputs = [
    encryptedAmountRandom.toString(),
    receiverEncRandom.toString(),
    auditorEncRandom.toString(),
    amount.toString(),
  ];

  const input = {
    privateInputs,
    publicInputs,
  };

  const proof = await generateGnarkProof("MINT", JSON.stringify(input));

  return { proof, publicInputs };
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
  auditorPublicKey: bigint[]
) => {
  return privateTransfer(
    user,
    userBalance,
    [0n, 1n],
    amount,
    userEncryptedBalance,
    auditorPublicKey
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
  auditorPublicKey: bigint[]
) => {
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

  const publicInputs = [
    ...sender.publicKey.map(String),
    ...senderEncryptedBalance.map(String),
    ...encryptedAmountSender[0].map(String),
    ...encryptedAmountSender[1].map(String),
    ...receiverPublicKey.map(String),
    ...encryptedAmountReceiver[0].map(String),
    ...encryptedAmountReceiver[1].map(String),
    ...receiverCiphertext.map(String),
    ...receiverAuthKey.map(String),
    receiverNonce.toString(),
    ...auditorPublicKey.map(String),
    ...auditorCiphertext.map(String),
    ...auditorAuthKey.map(String),
    auditorNonce.toString(),
  ];

  const privateInputs = [
    formatPrivKeyForBabyJub(sender.privateKey).toString(),
    senderBalance.toString(),
    encryptedAmountReceiverRandom.toString(),
    receiverEncRandom.toString(),
    auditorEncRandom.toString(),
    transferAmount.toString(),
  ];

  const input = {
    privateInputs,
    publicInputs,
  };

  const proof = await generateGnarkProof("TRANSFER", JSON.stringify(input));

  return {
    proof,
    publicInputs,
    senderBalancePCT: [
      ...senderCiphertext.map(String),
      ...senderAuthKey.map(String),
      senderNonce.toString(),
    ],
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
  length = 1
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
    length
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
 * @returns proof, publicInputs - Proof and public inputs for the generated proof
 * @returns userBalancePCT - User's balance after the withdrawal encrypted with Poseidon encryption
 */
export const withdraw = async (
  amount: bigint,
  user: User,
  userEncryptedBalance: bigint[],
  userBalance: bigint,
  auditorPublicKey: bigint[]
) => {
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

  const publicInputs = [
    ...userPublicKey.map(String),
    ...userEncryptedBalance.map(String),
    ...auditorPublicKey.map(String),
    ...auditorCiphertext.map(String),
    ...auditorAuthKey.map(String),
    auditorNonce.toString(),
    amount.toString(),
  ];

  const privateInputs = [
    formatPrivKeyForBabyJub(user.privateKey).toString(),
    userBalance.toString(),
    auditorEncRandom.toString(),
  ];

  const input = {
    privateInputs,
    publicInputs,
  };

  // generate proof
  const proof = await generateGnarkProof("WITHDRAW", JSON.stringify(input));

  return {
    proof,
    publicInputs,
    userBalancePCT: [
      ...userCiphertext.map(String),
      ...userAuthKey.map(String),
      userNonce.toString(),
    ],
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
  encryptedBalance: bigint[][]
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
    encryptedBalance[1]
  );

  // compare the decrypted balance with the calculated balance
  if (totalBalance !== 0n) {
    const expectedPoint = mulPointEscalar(Base8, totalBalance);
    expect(decryptedBalance).to.deep.equal(expectedPoint);
  }

  return totalBalance;
};
