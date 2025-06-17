import { Base8, type Point, mulPointEscalar } from "@zk-kit/baby-jubjub";
import {
	formatPrivKeyForBabyJub,
	genRandomBabyJubValue,
	poseidonDecrypt,
	poseidonEncrypt,
	genEcdhSharedKey,
} from "maci-crypto";
import { randomBytes } from "node:crypto";
import { BASE_POINT_ORDER } from "../constants";
import { poseidon } from "@zk-kit/poseidon";
import { bigint } from "hardhat/internal/core/params/argumentTypes";

/**
 * Generates a random nonce
 * @returns A cryptographically secure random number
 */
export const randomNonce = (): bigint => {
	const bytes = randomBytes(16);
	// add 1 to make sure it's non-zero
	return BigInt(`0x${bytes.toString("hex")}`) + 1n;
};

/**
 *
 * @param inputs Input array to encrypt
 * @param publicKey Public key
 * @returns ciphertext - Encrypted message
 * @returns nonce - Nonce used for the poseidon encryption
 * @returns encRandom - Randomness used for the encryption
 * @returns poseidonEncryptionKey - Encryption key (publicKey * encRandom)
 * @returns authKey - Authentication key (Base8 * encRandom)
 */
export const processPoseidonEncryption = (
	inputs: bigint[],
	publicKey: bigint[],
) => {
	const nonce = randomNonce();

	let encRandom = genRandomBabyJubValue();
	if (encRandom >= BASE_POINT_ORDER) {
		encRandom = genRandomBabyJubValue() / 10n;
	}

	const poseidonEncryptionKey = mulPointEscalar(
		publicKey as Point<bigint>,
		encRandom,
	);
	const authKey = mulPointEscalar(Base8, encRandom);
	const ciphertext = poseidonEncrypt(inputs, poseidonEncryptionKey, nonce);

	return { ciphertext, nonce, encRandom, poseidonEncryptionKey, authKey };
};

/**
 * Decrypts a message encrypted with Poseidon
 * @param ciphertext Encrypted message
 * @param authKey Authentication key
 * @param nonce Nonce used for the poseidon encryption
 * @param privateKey Private key
 * @param length Length of the original input array
 * @returns Decrypted message as an array
 */
export const processPoseidonDecryption = (
	ciphertext: bigint[],
	authKey: bigint[],
	nonce: bigint,
	privateKey: bigint,
	length: number,
) => {
	const sharedKey = mulPointEscalar(
		authKey as Point<bigint>,
		formatPrivKeyForBabyJub(privateKey),
	);

	const decrypted = poseidonDecrypt(ciphertext, sharedKey, nonce, length);

	return decrypted.slice(0, length);
};


export const pointToBigInt = (point: [bigint, bigint]): bigint => {
	const [x, y] = point;
	
	const xHex = x.toString(16).padStart(64, '0');
	const yHex = y.toString(16).padStart(64, '0');

	return BigInt('0x' + xHex + yHex);
};


export const processPoseidonEncryptionEcdh = (
	publicKey: bigint[], // This should be the public key of the recipient
	privateKey: bigint,
	message: string
) => {
	// Generate shared key using ECDH
	const pubKeyTuple: [bigint, bigint] = [BigInt(publicKey[0]), BigInt(publicKey[1])];
	const sharedKey = genEcdhSharedKey(privateKey, pubKeyTuple);

	const messageBuffer = Buffer.from(message, 'utf-8');
	const messageBigInt = BigInt('0x' + messageBuffer.toString('hex'));

	
	//const encRandom = sharedKey[0];
	
	const poseidonEncryptionKey = mulPointEscalar(
		pubKeyTuple as Point<bigint>,
		formatPrivKeyForBabyJub(privateKey)
	);
	
	// this just becomes the public key of the sender
	const authKey = mulPointEscalar(Base8, formatPrivKeyForBabyJub(privateKey));
	
	const nonce = randomNonce();
	const ciphertext = poseidonEncrypt([messageBigInt], poseidonEncryptionKey, nonce);
	return { ciphertext, nonce, poseidonEncryptionKey, authKey };
}



export const processPoseidonDecryptionEcdh = (
	publicKey: bigint[], // sender's public key
	privateKey: bigint, // recipient's private key
	encryptedMessage: bigint[],
	authKey: bigint[],
	nonce: bigint,
	length: number,
): string => {
	// Follow the same pattern as original decryption: sharedKey = authKey * privateKey
	const authKeyTuple: [bigint, bigint] = [BigInt(authKey[0]), BigInt(authKey[1])];
	const sharedKey = mulPointEscalar(
		authKeyTuple as Point<bigint>,
		formatPrivKeyForBabyJub(privateKey)
	);

	const decrypted = poseidonDecrypt(
		encryptedMessage,
		sharedKey,
		nonce, 
		length
	);

	// Convert decrypted bigint to string
	const decryptedHex = decrypted[0].toString(16);
	const decryptedBuffer = Buffer.from(decryptedHex, 'hex');
	return decryptedBuffer.toString('utf8');
};


export const processPoseidonDecryptionEcdhSender = (
	publicKey: bigint[], // receiver's public Key
	privateKey: bigint, // sender's private key
	encryptedMessage: bigint[],
	authKey: bigint[],
	nonce: bigint,
	length: number,
): string => {
	const sharedKey = mulPointEscalar(
		publicKey as Point<bigint>,
		formatPrivKeyForBabyJub(privateKey)
	);

	const decrypted = poseidonDecrypt(
		encryptedMessage,
		sharedKey, 
		nonce,
		length
	);

	const decryptedHex = decrypted[0].toString(16);
	const decryptedBuffer = Buffer.from(decryptedHex, 'hex');
	return decryptedBuffer.toString('utf8');
}


