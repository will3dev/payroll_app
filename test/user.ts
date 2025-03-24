import type { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/dist/src/signer-with-address";
import {
	formatPrivKeyForBabyJub,
	genPrivKey,
	genPubKey,
	hash2,
} from "maci-crypto";

export const AUDITOR_SECRET_KEY =
	12847321338015819245445518144028570538408927360876901642159872299055545378037n;

export class User {
	privateKey: bigint;
	publicKey: bigint[];
	signer: SignerWithAddress;

	constructor(signer: SignerWithAddress) {
		this.signer = signer;
		this.privateKey = genPrivKey();

		this.publicKey = genPubKey(this.privateKey);
	}

	static fromPrivateKey(signer: SignerWithAddress, privateKey: bigint) {
		const user = new User(signer);

		user.privateKey = privateKey;

		user.publicKey = genPubKey(privateKey);

		return user;
	}

	get address() {
		const address = hash2(this.publicKey);
		return address;
	}

	toZkInput(isSender = false) {
		if (isSender)
			return {
				senderPrivKey: formatPrivKeyForBabyJub(this.privateKey).toString(),
				senderPubKey: this.publicKey.map(String),
			};

		return {
			privKey: formatPrivKeyForBabyJub(this.privateKey).toString(),
			pubKey: this.publicKey.map(String),
		};
	}
}

export class BurnUser {
	privateKey: bigint;
	publicKey: bigint[];

	constructor() {
		this.privateKey = BigInt(0);
		this.publicKey = [0n, 1n];
	}

	get address() {
		const address = "0x1111111111111111111111111111111111111111";
		return address;
	}

	toZkInput(isSender = false) {
		if (isSender)
			return {
				// ! need to format for babyjub curve
				sk: formatPrivKeyForBabyJub(this.privateKey).toString(),
				sender_pk: this.publicKey.map(String),
			};
		return {
			// ! need to format for babyjub curve
			sk: formatPrivKeyForBabyJub(this.privateKey).toString(),
			pk: this.publicKey.map(String),
		};
	}
}
