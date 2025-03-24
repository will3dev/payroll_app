import type { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/dist/src/signer-with-address";
import { expect } from "chai";
import { ethers } from "hardhat";
import { poseidon3 } from "poseidon-lite";
import type { Registrar } from "../typechain-types/contracts/Registrar";
import {
	EncryptedERC__factory,
	Registrar__factory,
	SimpleERC20__factory,
	FeeERC20__factory,
} from "../typechain-types/factories/contracts";

import { formatPrivKeyForBabyJub } from "maci-crypto";
import type { EncryptedERC } from "../typechain-types/contracts/EncryptedERC";
import type { SimpleERC20 } from "../typechain-types/contracts/SimpleERC20";
import {
	deployLibrary,
	deployVerifiers,
	generateGnarkProof,
	getDecryptedBalance,
	privateTransfer,
	withdraw,
} from "./helpers";
import { User } from "./user";
import { processPoseidonEncryption } from "../src";
import { BN254_SCALAR_FIELD } from "../src/constants";
import type { FeeERC20 } from "../typechain-types/contracts/FeeERC20";

const DECIMALS = 10;

describe("EncryptedERC - Converter", () => {
	let registrar: Registrar;
	let users: User[];
	let signers: SignerWithAddress[];
	let owner: SignerWithAddress;
	let encryptedERC: EncryptedERC;
	let blacklistedERC20: SimpleERC20;
	let feeERC20: FeeERC20;
	const erc20s: SimpleERC20[] = [];

	const deployFixture = async () => {
		signers = await ethers.getSigners();
		owner = signers[0];

		const {
			registrationVerifier,
			mintVerifier,
			withdrawVerifier,
			transferVerifier,
		} = await deployVerifiers(owner);
		const babyJubJub = await deployLibrary(owner);

		for (const d of [6, 18, DECIMALS]) {
			// Deploy a simple ERC20 token
			const simpleERC20Factory = new SimpleERC20__factory(owner);
			const simpleERC20_ = await simpleERC20Factory
				.connect(owner)
				.deploy("Test", "TEST", d);
			await simpleERC20_.waitForDeployment();
			erc20s.push(simpleERC20_);
		}

		// Deploy an ERC20 token with fee
		const feeERC20Factory = new FeeERC20__factory(owner);
		feeERC20 = await feeERC20Factory
			.connect(owner)
			.deploy("Fee Token", "FEE", 18, 5, owner.address); // 5% fee
		await feeERC20.waitForDeployment();

		// Deploy an ERC20 token which will be blacklisted
		const blacklistedERC20Factory = new SimpleERC20__factory(owner);
		const blacklistedERC20_ = await blacklistedERC20Factory
			.connect(owner)
			.deploy("Blacklisted", "BL", 18);
		await blacklistedERC20_.waitForDeployment();
		blacklistedERC20 = blacklistedERC20_;

		// Deploy the registrar contract
		const registrarFactory = new Registrar__factory(owner);
		const registrar_ = await registrarFactory
			.connect(owner)
			.deploy(registrationVerifier);

		await registrar_.waitForDeployment();

		// Deploy the Converter EncryptedERC contract
		const encryptedERCFactory = new EncryptedERC__factory({
			"contracts/libraries/BabyJubJub.sol:BabyJubJub": babyJubJub,
		});
		const encryptedERC_ = await encryptedERCFactory.connect(owner).deploy({
			registrar: registrar_.target,
			isConverter: true,
			name: "Test",
			symbol: "TEST",
			mintVerifier,
			withdrawVerifier,
			transferVerifier,
			decimals: DECIMALS,
		});

		await encryptedERC_.waitForDeployment();

		registrar = registrar_;
		encryptedERC = encryptedERC_;
		users = signers.map((signer) => new User(signer));
	};

	before(async () => await deployFixture());

	describe("Registrar", () => {
		it("should deploy registrar properly", async () => {
			expect(registrar.target).to.not.be.null;
			expect(registrar).to.not.be.null;
		});

		it("should initialize properly", async () => {
			const burnUserAddress = await registrar.burnUser();
			const burnUserPublicKey = await registrar.userPublicKeys(burnUserAddress);
			expect(burnUserPublicKey).to.deep.equal([0n, 1n]);
		});

		describe("Registration", () => {
			let validParamsForUser4: {
				proof: string[];
				publicInputs: string[];
			};

			it("users should be able to register properly", async () => {
				const network = await ethers.provider.getNetwork();
				const chainId = BigInt(network.chainId);

				for (const user of users.slice(0, 5)) {
					const privateInputs = [
						formatPrivKeyForBabyJub(user.privateKey).toString(),
					];

					const fullAddress = BigInt(user.signer.address);

					const publicInputs = [
						...user.publicKey.map(String),
						fullAddress.toString(),
						chainId.toString(),
					];
					const input = {
						privateInputs,
						publicInputs,
					};

					const registrationHash = poseidon3([
						chainId,
						formatPrivKeyForBabyJub(user.privateKey).toString(),
						fullAddress,
					]).toString();

					input.publicInputs.push(registrationHash);

					const proof = await generateGnarkProof(
						"REGISTER",
						JSON.stringify(input),
					);

					const tx = await registrar
						.connect(user.signer)
						.register(
							proof.map(BigInt),
							publicInputs.map(BigInt) as [
								bigint,
								bigint,
								bigint,
								bigint,
								bigint,
							],
						);
					await tx.wait();

					// check if the user is registered
					expect(await registrar.isUserRegistered(user.signer.address)).to.be
						.true;

					// and the public key is set
					const publicKey = await registrar.getUserPublicKey(
						user.signer.address,
					);

					validParamsForUser4 = { proof, publicInputs };

					expect(publicKey).to.deep.equal(user.publicKey);
				}
			});

			it("should revert if chain ID is invalid", async () => {
				const user = users[0];
				const network = await ethers.provider.getNetwork();
				const chainId = BigInt(network.chainId) + 1n; // Invalid chain ID

				const privateInputs = [
					formatPrivKeyForBabyJub(user.privateKey).toString(),
				];

				const fullAddress = BigInt(user.signer.address);

				const publicInputs = [
					...user.publicKey.map(String),
					fullAddress.toString(),
					chainId.toString(),
				];
				const input = {
					privateInputs,
					publicInputs,
				};

				const registrationHash = poseidon3([
					chainId,
					formatPrivKeyForBabyJub(user.privateKey).toString(),
					fullAddress,
				]).toString();

				input.publicInputs.push(registrationHash);

				const proof = await generateGnarkProof(
					"REGISTER",
					JSON.stringify(input),
				);

				await expect(
					registrar
						.connect(user.signer)
						.register(
							proof.map(BigInt),
							publicInputs.map(BigInt) as [
								bigint,
								bigint,
								bigint,
								bigint,
								bigint,
							],
						),
				).to.be.revertedWithCustomError(registrar, "InvalidChainId");
			});

			it("should revert if user is already registered", async () => {
				const user = users[0];
				const network = await ethers.provider.getNetwork();
				const chainId = BigInt(network.chainId);

				const privateInputs = [
					formatPrivKeyForBabyJub(user.privateKey).toString(),
				];

				const fullAddress = BigInt(user.signer.address);

				const publicInputs = [
					...user.publicKey.map(String),
					fullAddress.toString(),
					chainId.toString(),
				];
				const input = {
					privateInputs,
					publicInputs,
				};

				const registrationHash = poseidon3([
					chainId,
					formatPrivKeyForBabyJub(user.privateKey).toString(),
					fullAddress,
				]).toString();

				input.publicInputs.push(registrationHash);

				const proof = await generateGnarkProof(
					"REGISTER",
					JSON.stringify(input),
				);

				await expect(
					registrar
						.connect(user.signer)
						.register(
							proof.map(BigInt),
							publicInputs.map(BigInt) as [
								bigint,
								bigint,
								bigint,
								bigint,
								bigint,
							],
						),
				).to.be.revertedWithCustomError(registrar, "UserAlreadyRegistered");
			});

			it("should revert if registration hash is greater than or equal to BabyJubJub.Q", async () => {
				const user = users[4];

				const inputs = [...validParamsForUser4.publicInputs];

				inputs[4] = String(BN254_SCALAR_FIELD + 1n);

				await expect(
					registrar
						.connect(user.signer)
						.register(
							validParamsForUser4.proof.map(BigInt),
							inputs.map(BigInt) as [bigint, bigint, bigint, bigint, bigint],
						),
				).to.be.revertedWithCustomError(registrar, "InvalidRegistrationHash");
			});
		});
	});

	describe("EncryptedERC", () => {
		let auditorPublicKey: [bigint, bigint];

		it("should initialize properly", async () => {
			expect(encryptedERC.target).to.not.be.null;
			expect(encryptedERC).to.not.be.null;

			// since eerc is standalone name and symbol should not be set
			expect(await encryptedERC.name()).to.equal("");
			expect(await encryptedERC.symbol()).to.equal("");

			// auditor key should not be set
			expect(await encryptedERC.isAuditorKeySet()).to.be.false;
		});

		it("should revert if auditor key is not set", async () => {
			await expect(
				encryptedERC.connect(users[0].signer).privateMint(
					users[0].signer.address,
					Array.from({ length: 8 }, () => 1n),
					Array.from({ length: 24 }, () => 1n),
				),
			).to.be.reverted;
		});

		it("should revert if user try to private mint", async () => {
			await expect(
				encryptedERC.connect(users[0].signer).privateMint(
					users[0].signer.address,
					Array.from({ length: 8 }, () => 1n),
					Array.from({ length: 24 }, () => 1n),
				),
			).to.be.reverted;
		});

		describe("Auditor Key Set", () => {
			it("can not deposit if auditor key is not set", async () => {
				await expect(
					encryptedERC.connect(users[0].signer).deposit(
						1n,
						erc20s[0].target,
						Array.from({ length: 7 }, () => 1n),
					),
				).to.be.reverted;
			});

			it("only owner can set auditor key", async () => {
				await expect(
					encryptedERC
						.connect(users[4].signer)
						.setAuditorPublicKey(users[0].signer.address),
				).to.be.reverted;
			});

			it("owner can set auditor key", async () => {
				const tx = await encryptedERC
					.connect(owner)
					.setAuditorPublicKey(owner.address);
				await tx.wait();

				expect(await encryptedERC.isAuditorKeySet()).to.be.true;
			});

			it("auditor and auditor key should be set", async () => {
				const auditor = await encryptedERC.auditor();
				const auditorKey = await encryptedERC.auditorPublicKey();

				expect(auditor).to.equal(users[0].signer.address);
				expect(auditorKey).to.deep.equal([
					users[0].publicKey[0],
					users[0].publicKey[1],
				]);

				auditorPublicKey = [users[0].publicKey[0], users[0].publicKey[1]];
			});

			it("should revert if user try to private burn in converter", async () => {
				await expect(
					encryptedERC.connect(users[0].signer).privateBurn(
						Array.from({ length: 8 }, () => 1n),
						Array.from({ length: 32 }, () => 1n),
						Array.from({ length: 7 }, () => 1n),
					),
				).to.be.revertedWithCustomError(encryptedERC, "InvalidOperation");
			});
		});

		describe("Depositing Tokens - Higher ERC20 Decimals (18)", () => {
			const mintAmount = 1000000000000000000000000000n;
			let userEncryptedBalance = 0n;

			it("should initialize user balance to 0", async () => {
				const ownerUser = users[0];
				const balance = await encryptedERC.balanceOf(
					ownerUser.signer.address,
					1,
				);

				const totalBalance = await getDecryptedBalance(
					ownerUser.privateKey,
					balance.amountPCTs,
					balance.balancePCT,
					balance.eGCT,
				);

				userEncryptedBalance = totalBalance;
			});

			it("mint some tokens to the owner", async () => {
				const erc20 = erc20s[1];
				const tx = await erc20.connect(owner).mint(owner.address, mintAmount);
				await tx.wait();

				const balance = await erc20.balanceOf(owner.address);
				expect(balance).to.equal(mintAmount);
			});

			it("should deposit tokens to EncryptedERC and return the dust properly and mint the proper balance", async () => {
				const ownerUser = users[0];
				const erc20 = erc20s[1];

				const cases = [
					{
						convertedAmount: 1_005_000_000_000_000_000_000n,
						dust: 0n,
						encryptedValue: 10_050_000_000_000n,
					},
					{
						convertedAmount: 1_000_000_000_000_000_000_000n,
						dust: 0n,
						encryptedValue: 10_000_000_000_000n,
					},
					{
						convertedAmount: 1_000_000_001n,
						dust: 1n,
						encryptedValue: 10n,
					},
					{
						convertedAmount: 1_000_000_001_000_000_000n,
						dust: 0n,
						encryptedValue: 10_000_000_010n,
					},
					{
						convertedAmount: 100_000_000n,
						dust: 0n,
						encryptedValue: 1n,
					},
					{
						convertedAmount: 50_000_000n,
						dust: 50_000_000n,
						encryptedValue: 0n,
					},
					{
						convertedAmount: 1_234_567_890n,
						dust: 34_567_890n,
						encryptedValue: 12n,
					},
				];

				for (const testCase of cases) {
					// approve the deposit
					await erc20
						.connect(owner)
						.approve(encryptedERC.target, testCase.convertedAmount);

					const erc20BalanceBefore = await erc20.balanceOf(owner.address);

					// need to create a new pct for the amount
					const { ciphertext, nonce, authKey } = processPoseidonEncryption(
						[testCase.encryptedValue],
						ownerUser.publicKey,
					);

					await encryptedERC
						.connect(owner)
						.deposit(testCase.convertedAmount, erc20.target, [
							...ciphertext,
							...authKey,
							nonce,
						]);

					const erc20BalanceAfter = await erc20.balanceOf(owner.address);
					expect(erc20BalanceAfter).to.equal(
						erc20BalanceBefore - testCase.convertedAmount + testCase.dust,
					);

					const balance = await encryptedERC.balanceOf(
						ownerUser.signer.address,
						1,
					);

					const totalBalance = await getDecryptedBalance(
						ownerUser.privateKey,
						balance.amountPCTs,
						balance.balancePCT,
						balance.eGCT,
					);

					expect(totalBalance).to.equal(
						userEncryptedBalance + testCase.encryptedValue,
					);
					userEncryptedBalance = totalBalance;
				}
			});

			it("should revert if amount approved is different from the amount deposited", async () => {
				const ownerUser = users[0];
				const depositAmount = 1_000_000_000n;

				// Mint some tokens to the owner
				await feeERC20.connect(owner).mint(owner.address, depositAmount * 10n);

				// Approve the deposit
				await feeERC20
					.connect(owner)
					.approve(encryptedERC.target, depositAmount);

				// Create the encrypted value
				const { ciphertext, nonce, authKey } = processPoseidonEncryption(
					[10n],
					ownerUser.publicKey,
				);

				await expect(
					encryptedERC
						.connect(owner)
						.deposit(depositAmount, feeERC20.target, [
							...ciphertext,
							...authKey,
							nonce,
						]),
				).to.be.revertedWithCustomError(encryptedERC, "TransferFailed");
			});

			// this test should be here because it needs the encryptedERC to be initialized and deposit to be done
			it("get tokens should return the proper addresses", async () => {
				const contractTokens = await encryptedERC.getTokens();
				expect(contractTokens).to.deep.equal([erc20s[1].target]);
			});

			it("should revert if user is not registered", async () => {
				await expect(
					encryptedERC.connect(users[5].signer).deposit(
						1n,
						users[0].signer.address,
						Array.from({ length: 7 }, () => 1n),
					),
				).to.be.reverted;
			});

			it("should revert if the token is blacklisted", async () => {
				await expect(
					encryptedERC.connect(users[0].signer).deposit(
						1n,
						blacklistedERC20.target,
						Array.from({ length: 7 }, () => 1n),
					),
				).to.be.reverted;
			});
		});

		describe("Depositing Tokens - Lower ERC20 Decimals (6)", () => {
			const mintAmount = 1000000000000000000000000n;
			let userEncryptedBalance = 0n;

			it("mint some tokens to the owner", async () => {
				const erc20 = erc20s[0];

				const tx = await erc20.connect(owner).mint(owner.address, mintAmount);
				await tx.wait();

				const balance = await erc20.balanceOf(owner.address);
				expect(balance).to.equal(mintAmount);
			});

			it("should initialize user balance to 0", async () => {
				const ownerUser = users[0];
				const balance = await encryptedERC.getBalanceFromTokenAddress(
					ownerUser.signer.address,
					erc20s[0].target,
				);

				const totalBalance = await getDecryptedBalance(
					ownerUser.privateKey,
					balance.amountPCTs,
					balance.balancePCT,
					balance.eGCT,
				);
				userEncryptedBalance = totalBalance;
			});

			it("should deposit tokens to EncryptedERC and return the dust properly and mint the proper balance", async () => {
				const ownerUser = users[0];

				const cases = [
					{
						convertedAmount: 1_000_000n,
						dust: 0n,
						encryptedValue: 10_000_000_000n,
					},
					{
						convertedAmount: 1_000_001n,
						dust: 0n,
						encryptedValue: 10_000_010_000n,
					},
					{
						convertedAmount: 500_000n,
						dust: 0n,
						encryptedValue: 5_000_000_000n,
					},
					{
						convertedAmount: 123_456_789n,
						dust: 0n,
						encryptedValue: 1_234_567_890_000n,
					},
				];

				const erc20 = erc20s[0];

				for (const testCase of cases) {
					// approve the deposit
					await erc20
						.connect(owner)
						.approve(encryptedERC.target, testCase.convertedAmount);

					const erc20BalanceBefore = await erc20.balanceOf(owner.address);

					// need to create a new pct for the amount pct
					const { ciphertext, nonce, authKey } = processPoseidonEncryption(
						[testCase.encryptedValue],
						ownerUser.publicKey,
					);

					await encryptedERC
						.connect(owner)
						.deposit(testCase.convertedAmount, erc20.target, [
							...ciphertext,
							...authKey,
							nonce,
						]);

					const erc20BalanceAfter = await erc20.balanceOf(owner.address);
					expect(erc20BalanceAfter).to.equal(
						erc20BalanceBefore - testCase.convertedAmount + testCase.dust,
					);

					const balance = await encryptedERC.balanceOf(
						ownerUser.signer.address,
						2,
					);

					const totalBalance = await getDecryptedBalance(
						ownerUser.privateKey,
						balance.amountPCTs,
						balance.balancePCT,
						balance.eGCT,
					);

					expect(totalBalance).to.equal(
						userEncryptedBalance + testCase.encryptedValue,
					);
					userEncryptedBalance = totalBalance;
				}
			});

			it("get tokens should return the proper addresses", async () => {
				const contractTokens = await encryptedERC.getTokens();
				expect(contractTokens).to.deep.equal([
					erc20s[1].target,
					erc20s[0].target,
				]);
			});

			it("should revert of user does not have enough token or enough approval for the deposit", async () => {
				const user = users[1];

				await expect(
					encryptedERC.connect(user.signer).deposit(
						1n,
						erc20s[0].target,
						Array.from({ length: 7 }, () => 1n),
					),
				).to.be.reverted;
			});
		});

		describe("Depositing Tokens - Same ERC20 Decimals (10)", () => {
			const mintAmount = 1000000000000000000000000n;
			let userEncryptedBalance = 0n;

			it("mint some tokens to the owner", async () => {
				const erc20 = erc20s[2];

				const tx = await erc20.connect(owner).mint(owner.address, mintAmount);
				await tx.wait();

				const balance = await erc20.balanceOf(owner.address);
				expect(balance).to.equal(mintAmount);
			});

			it("should initialize user balance to 0", async () => {
				const ownerUser = users[0];
				const balance = await encryptedERC.balanceOf(
					ownerUser.signer.address,
					3,
				);

				const totalBalance = await getDecryptedBalance(
					ownerUser.privateKey,
					balance.amountPCTs,
					balance.balancePCT,
					balance.eGCT,
				);
				userEncryptedBalance = totalBalance;
			});

			it("should deposit tokens to EncryptedERC and return the dust properly and mint the proper balance", async () => {
				const ownerUser = users[0];

				const cases = [
					{
						convertedAmount: 1_000_000_000n,
						dust: 0n,
						encryptedValue: 1_000_000_000n,
					},
					{
						convertedAmount: 123_456_789_000n,
						dust: 0n,
						encryptedValue: 123_456_789_000n,
					},
					{
						convertedAmount: 50_000_000_000n,
						dust: 0n,
						encryptedValue: 50_000_000_000n,
					},
					{
						convertedAmount: 1_000n,
						dust: 0n,
						encryptedValue: 1_000n,
					},
					{
						convertedAmount: 999_999_999_999n,
						dust: 0n,
						encryptedValue: 999_999_999_999n,
					},
				];

				const erc20 = erc20s[2];

				for (const testCase of cases) {
					// approve the deposit
					await erc20
						.connect(owner)
						.approve(encryptedERC.target, testCase.convertedAmount);

					const erc20BalanceBefore = await erc20.balanceOf(owner.address);

					// need to create a new pct for the amount pct
					const { ciphertext, nonce, authKey } = processPoseidonEncryption(
						[testCase.encryptedValue],
						ownerUser.publicKey,
					);

					await encryptedERC
						.connect(owner)
						.deposit(testCase.convertedAmount, erc20.target, [
							...ciphertext,
							...authKey,
							nonce,
						]);

					const erc20BalanceAfter = await erc20.balanceOf(owner.address);
					expect(erc20BalanceAfter).to.equal(
						erc20BalanceBefore - testCase.convertedAmount + testCase.dust,
					);

					const balance = await encryptedERC.balanceOf(
						ownerUser.signer.address,
						3,
					);

					const totalBalance = await getDecryptedBalance(
						ownerUser.privateKey,
						balance.amountPCTs,
						balance.balancePCT,
						balance.eGCT,
					);

					expect(totalBalance).to.equal(
						userEncryptedBalance + testCase.encryptedValue,
					);
					userEncryptedBalance = totalBalance;
				}
			});

			it("get tokens should return the proper addresses", async () => {
				const contractTokens = await encryptedERC.getTokens();
				expect(contractTokens).to.deep.equal([
					erc20s[1].target,
					erc20s[0].target,
					erc20s[2].target,
				]);
			});
		});

		describe("Blacklisting Tokens", () => {
			it("set token as blacklisted", async () => {
				await encryptedERC
					.connect(owner)
					.setTokenBlacklist(blacklistedERC20.target, true);

				const isBlacklisted = await encryptedERC.isTokenBlacklisted(
					blacklistedERC20.target,
				);
				expect(isBlacklisted).to.equal(true);
			});

			it("should revert if user is not owner", async () => {
				const user = users[1].signer;

				await expect(
					encryptedERC
						.connect(user)
						.setTokenBlacklist(blacklistedERC20.target, true),
				).to.be.reverted;
			});

			it("should revert if token is blacklisted", async () => {
				const user = users[0];

				await expect(
					encryptedERC.connect(user.signer).deposit(
						1n,
						blacklistedERC20.target,
						Array.from({ length: 7 }, () => 1n),
					),
				).to.be.reverted;
			});
		});

		describe("Withdrawing Tokens - Lower ERC20 Decimals (6)", () => {
			const tokenId = 2;
			const withdrawAmount = 1000n;
			let userInitialBalance: bigint;
			let validProof: {
				proof: string[];
				publicInputs: string[];
				userBalancePCT: string[];
			};

			it("should initialize user balance properly", async () => {
				const user = users[0];

				const balance = await encryptedERC.balanceOf(
					user.signer.address,
					tokenId,
				);

				const totalBalance = await getDecryptedBalance(
					user.privateKey,
					balance.amountPCTs,
					balance.balancePCT,
					balance.eGCT,
				);

				userInitialBalance = totalBalance;
			});

			it("should withdraw token properly", async () => {
				const user = users[0];
				const balance = await encryptedERC.balanceOf(
					user.signer.address,
					tokenId,
				);
				const userEncryptedBalance = [...balance.eGCT.c1, ...balance.eGCT.c2];

				const { proof, publicInputs, userBalancePCT } = await withdraw(
					withdrawAmount,
					user,
					userEncryptedBalance,
					userInitialBalance,
					auditorPublicKey,
				);

				expect(
					await encryptedERC
						.connect(user.signer)
						.withdraw(tokenId, proof, publicInputs, userBalancePCT),
				).to.be.not.reverted;

				validProof = { proof, publicInputs, userBalancePCT };
			});

			it("after withdrawing, the user balance should be updated properly", async () => {
				const user = users[0];
				const balance = await encryptedERC.balanceOf(
					user.signer.address,
					tokenId,
				);

				const totalBalance = await getDecryptedBalance(
					user.privateKey,
					balance.amountPCTs,
					balance.balancePCT,
					balance.eGCT,
				);

				expect(totalBalance).to.equal(userInitialBalance - withdrawAmount);
			});

			it("should revert if public keys are not matching", async () => {
				const user = users[1];

				await expect(
					encryptedERC
						.connect(user.signer)
						.withdraw(
							tokenId,
							validProof.proof,
							validProof.publicInputs,
							validProof.userBalancePCT,
						),
				).to.be.revertedWithCustomError(encryptedERC, "InvalidProof");
			});

			it("should revert if auditor public key is not matching", async () => {
				const _publicInputs = [...validProof.publicInputs];
				_publicInputs[6] = "0";
				_publicInputs[7] = "0";

				await expect(
					encryptedERC
						.connect(users[0].signer)
						.withdraw(
							tokenId,
							validProof.proof,
							_publicInputs,
							validProof.userBalancePCT,
						),
				).to.be.revertedWithCustomError(encryptedERC, "InvalidProof");
			});

			it("should revert if proof is not valid", async () => {
				const user = users[0];
				const _proof = [...validProof.proof];
				_proof[0] = "0";

				await expect(
					encryptedERC
						.connect(user.signer)
						.withdraw(
							tokenId,
							validProof.proof,
							validProof.publicInputs,
							validProof.userBalancePCT,
						),
				).to.be.revertedWithCustomError(encryptedERC, "InvalidProof");
			});

			it("should revert if token is not registered", async () => {
				const user = users[0];

				await expect(
					encryptedERC
						.connect(user.signer)
						.withdraw(
							10n,
							validProof.proof,
							validProof.publicInputs,
							validProof.userBalancePCT,
						),
				).to.be.revertedWithCustomError(encryptedERC, "UnknownToken");
			});
		});

		describe("Withdrawing Tokens - Same ERC20 Decimals (10)", () => {
			const tokenId = 3;
			const withdrawAmount = 1000n;
			let userInitialBalance: bigint;
			let validProof: {
				proof: string[];
				publicInputs: string[];
				userBalancePCT: string[];
			};

			it("should initialize user balance properly", async () => {
				const user = users[0];

				const balance = await encryptedERC.balanceOf(
					user.signer.address,
					tokenId,
				);

				const totalBalance = await getDecryptedBalance(
					user.privateKey,
					balance.amountPCTs,
					balance.balancePCT,
					balance.eGCT,
				);

				userInitialBalance = totalBalance;
			});

			it("should withdraw token properly", async () => {
				const user = users[0];
				const balance = await encryptedERC.balanceOf(
					user.signer.address,
					tokenId,
				);
				const userEncryptedBalance = [...balance.eGCT.c1, ...balance.eGCT.c2];

				const { proof, publicInputs, userBalancePCT } = await withdraw(
					withdrawAmount,
					user,
					userEncryptedBalance,
					userInitialBalance,
					auditorPublicKey,
				);

				expect(
					await encryptedERC
						.connect(user.signer)
						.withdraw(tokenId, proof, publicInputs, userBalancePCT),
				).to.be.not.reverted;

				validProof = { proof, publicInputs, userBalancePCT };
			});

			it("after withdrawing, the user balance should be updated properly", async () => {
				const user = users[0];
				const balance = await encryptedERC.balanceOf(
					user.signer.address,
					tokenId,
				);

				const totalBalance = await getDecryptedBalance(
					user.privateKey,
					balance.amountPCTs,
					balance.balancePCT,
					balance.eGCT,
				);

				expect(totalBalance).to.equal(userInitialBalance - withdrawAmount);
			});

			it("should revert if user public key X and public key X from proof are not matching", async () => {
				const user = users[0];

				const inputs = [...validProof.publicInputs];

				inputs[0] = "100";

				await expect(
					encryptedERC
						.connect(user.signer)
						.withdraw(
							tokenId,
							validProof.proof,
							inputs,
							validProof.userBalancePCT,
						),
				).to.be.revertedWithCustomError(encryptedERC, "InvalidProof");
			});

			it("should revert if user public key Y and public key Y from proof are not matching", async () => {
				const user = users[0];

				const inputs = [...validProof.publicInputs];

				inputs[1] = "100";

				await expect(
					encryptedERC
						.connect(user.signer)
						.withdraw(
							tokenId,
							validProof.proof,
							inputs,
							validProof.userBalancePCT,
						),
				).to.be.revertedWithCustomError(encryptedERC, "InvalidProof");
			});

			it("should revert if auditor public key X and public key X from proof are not matching", async () => {
				const _publicInputs = [...validProof.publicInputs];
				_publicInputs[6] = "0";

				await expect(
					encryptedERC
						.connect(users[0].signer)
						.withdraw(
							tokenId,
							validProof.proof,
							_publicInputs,
							validProof.userBalancePCT,
						),
				).to.be.revertedWithCustomError(encryptedERC, "InvalidProof");
			});

			it("should revert if auditor public key Y and public key Y from proof are not matching", async () => {
				const _publicInputs = [...validProof.publicInputs];
				_publicInputs[7] = "0";

				await expect(
					encryptedERC
						.connect(users[0].signer)
						.withdraw(
							tokenId,
							validProof.proof,
							_publicInputs,
							validProof.userBalancePCT,
						),
				).to.be.revertedWithCustomError(encryptedERC, "InvalidProof");
			});

			it("should revert if proof is not valid", async () => {
				const user = users[0];
				const _proof = [...validProof.proof];
				_proof[0] = "0";

				await expect(
					encryptedERC
						.connect(user.signer)
						.withdraw(
							tokenId,
							validProof.proof,
							validProof.publicInputs,
							validProof.userBalancePCT,
						),
				).to.be.revertedWithCustomError(encryptedERC, "InvalidProof");
			});

			it("should revert if token is not registered", async () => {
				const user = users[0];

				await expect(
					encryptedERC
						.connect(user.signer)
						.withdraw(
							10n,
							validProof.proof,
							validProof.publicInputs,
							validProof.userBalancePCT,
						),
				).to.be.revertedWithCustomError(encryptedERC, "UnknownToken");
			});
		});

		describe("Withdrawing Tokens - Higher ERC20 Decimals (18)", () => {
			const tokenId = 1;
			const withdrawAmount = 10000n;
			let userInitialBalance: bigint;
			let validProof: {
				proof: string[];
				publicInputs: string[];
				userBalancePCT: string[];
			};

			it("should initialize user balance properly", async () => {
				const user = users[0];
				const balance = await encryptedERC.balanceOf(
					user.signer.address,
					tokenId,
				);

				const totalBalance = await getDecryptedBalance(
					user.privateKey,
					balance.amountPCTs,
					balance.balancePCT,
					balance.eGCT,
				);

				userInitialBalance = totalBalance;
			});

			it("should withdraw token properly", async () => {
				const user = users[0];
				const balance = await encryptedERC.balanceOf(
					user.signer.address,
					tokenId,
				);
				const userEncryptedBalance = [...balance.eGCT.c1, ...balance.eGCT.c2];

				const { proof, publicInputs, userBalancePCT } = await withdraw(
					withdrawAmount,
					user,
					userEncryptedBalance,
					userInitialBalance,
					auditorPublicKey,
				);

				expect(
					await encryptedERC
						.connect(user.signer)
						.withdraw(tokenId, proof, publicInputs, userBalancePCT),
				).to.be.not.reverted;

				validProof = { proof, publicInputs, userBalancePCT };
			});

			it("after withdrawing, the user balance should be updated properly", async () => {
				const user = users[0];
				const balance = await encryptedERC.balanceOf(
					user.signer.address,
					tokenId,
				);

				const totalBalance = await getDecryptedBalance(
					user.privateKey,
					balance.amountPCTs,
					balance.balancePCT,
					balance.eGCT,
				);

				expect(totalBalance).to.equal(userInitialBalance - withdrawAmount);
			});
		});

		describe("Transferring Tokens - 1", () => {
			let senderBalance: bigint; // hardcoded for now from the deposit test
			const transferAmount = 1000n;

			it("sender balance should initialized properly", async () => {
				const sender = users[0];

				const balance = await encryptedERC.balanceOf(sender.signer.address, 1);

				const totalBalance = await getDecryptedBalance(
					sender.privateKey,
					balance.amountPCTs,
					balance.balancePCT,
					balance.eGCT,
				);

				senderBalance = totalBalance;
			});

			it("should transfer tokens properly", async () => {
				const sender = users[0];
				const receiver = users[1];

				const balance = await encryptedERC.balanceOf(sender.signer.address, 1);
				const senderEncryptedBalance = [...balance.eGCT.c1, ...balance.eGCT.c2];

				const { proof, publicInputs, senderBalancePCT } = await privateTransfer(
					sender,
					senderBalance,
					receiver.publicKey,
					transferAmount,
					senderEncryptedBalance,
					auditorPublicKey,
				);

				expect(
					await encryptedERC
						.connect(sender.signer)
						.transfer(
							receiver.signer.address,
							1n,
							proof,
							publicInputs,
							senderBalancePCT,
						),
				).to.be.not.reverted;

				senderBalance = senderBalance - transferAmount;
			});

			it("sender balance should be updated properly", async () => {
				const sender = users[0];

				const balance = await encryptedERC.balanceOf(sender.signer.address, 1);

				const totalBalance = await getDecryptedBalance(
					sender.privateKey,
					balance.amountPCTs,
					balance.balancePCT,
					balance.eGCT,
				);

				expect(totalBalance).to.equal(senderBalance);
			});

			it("receiver balance should be updated properly", async () => {
				const receiver = users[1];

				const balance = await encryptedERC.balanceOf(
					receiver.signer.address,
					1,
				);

				const totalBalance = await getDecryptedBalance(
					receiver.privateKey,
					balance.amountPCTs,
					balance.balancePCT,
					balance.eGCT,
				);

				expect(totalBalance).to.equal(transferAmount);
			});
		});

		describe("Transferring Tokens - 2", () => {
			let senderBalance: bigint; // hardcoded for now from the deposit test
			const transferAmount = 1000n;

			it("sender balance should initialized properly", async () => {
				const sender = users[0];

				const balance = await encryptedERC.balanceOf(sender.signer.address, 2);

				const totalBalance = await getDecryptedBalance(
					sender.privateKey,
					balance.amountPCTs,
					balance.balancePCT,
					balance.eGCT,
				);

				senderBalance = totalBalance;
			});

			it("should transfer tokens properly", async () => {
				const sender = users[0];
				const receiver = users[1];

				const balance = await encryptedERC.balanceOf(sender.signer.address, 2);
				const senderEncryptedBalance = [...balance.eGCT.c1, ...balance.eGCT.c2];

				const { proof, publicInputs, senderBalancePCT } = await privateTransfer(
					sender,
					senderBalance,
					receiver.publicKey,
					transferAmount,
					senderEncryptedBalance,
					auditorPublicKey,
				);

				expect(
					await encryptedERC
						.connect(sender.signer)
						.transfer(
							receiver.signer.address,
							2n,
							proof,
							publicInputs,
							senderBalancePCT,
						),
				).to.be.not.reverted;

				senderBalance = senderBalance - transferAmount;
			});

			it("sender balance should be updated properly", async () => {
				const sender = users[0];

				const balance = await encryptedERC.balanceOf(sender.signer.address, 2);

				const totalBalance = await getDecryptedBalance(
					sender.privateKey,
					balance.amountPCTs,
					balance.balancePCT,
					balance.eGCT,
				);

				expect(totalBalance).to.equal(senderBalance);
			});

			it("receiver balance should be updated properly", async () => {
				const receiver = users[1];

				const balance = await encryptedERC.balanceOf(
					receiver.signer.address,
					2,
				);

				const totalBalance = await getDecryptedBalance(
					receiver.privateKey,
					balance.amountPCTs,
					balance.balancePCT,
					balance.eGCT,
				);

				expect(totalBalance).to.equal(transferAmount);
			});
		});
	});
});
