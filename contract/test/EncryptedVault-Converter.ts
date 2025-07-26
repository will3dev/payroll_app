import type { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/dist/src/signer-with-address";
import { expect } from "chai";
import { ethers, zkit } from "hardhat";
import type { Registrar } from "../typechain-types/contracts/Registrar";
import {
	EncryptedERC__factory,
	Registrar__factory,
} from "../typechain-types/factories/contracts";
import {
	EncryptedVault__factory,
	EncryptedVaultBalances__factory,
	EncryptedVaultManager__factory,
} from "../typechain-types/factories/contracts/Vault";
import type {
	EncryptedVault,
	EncryptedVaultBalances,
	EncryptedVaultManager,
} from "../typechain-types/contracts/Vault";
import type {
	CalldataWithdrawCircuitGroth16,
	RegistrationCircuit,
} from "../generated-types/zkit";
import { processPoseidonEncryption, processPoseidonDecryption } from "../src";
import {
	type FeeERC20,
	FeeERC20__factory,
	type SimpleERC20,
	SimpleERC20__factory,
} from "../typechain-types";
import type {
	EncryptedERC,
	MintProofStruct,
	TransferProofStruct,
} from "../typechain-types/contracts/EncryptedERC";
import {
	decryptPCT,
	deployLibrary,
	deployVerifiers,
	getDecryptedBalance,
	privateTransfer,
	withdraw,
} from "./helpers";
import { User } from "./user";
import {
	processPoseidonEncryptionEcdh,
	processPoseidonDecryptionEcdh,
	processPoseidonDecryptionEcdhSender
  } from "../src/poseidon/poseidon";

import {
	calculateMaxDraw,
	vaultWithdrawal
} from "./vaultHelpers";
import {encryptMessage } from "../src/jub/jub";

const DECIMALS = 10;


describe("EncryptedVault - Converter", () => {
	let registrar: Registrar;
	let users: User[];
	let signers: SignerWithAddress[];
	let owner: SignerWithAddress;
	let encryptedVault: EncryptedVault;
	let encryptedVaultBalances: EncryptedVaultBalances;
	let encryptedVaultManager: EncryptedVaultManager;
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
			batchTransferVerifier,
			vaultWithdrawalVerifier,
		} = await deployVerifiers(owner, false);
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

		// Deploy the Converter EncryptedVault contract
		const encryptedVaultFactory = new EncryptedVault__factory({
			"contracts/libraries/BabyJubJub.sol:BabyJubJub": babyJubJub,
		});
		
		
		
		// Deploy the EncryptedVault contract
		const encryptedVault_ = await encryptedVaultFactory.connect(owner).deploy({
			registrar: registrar_.target,
			isConverter: true,
			name: "Test",
			symbol: "TEST",
			mintVerifier,
			withdrawVerifier,
			transferVerifier,
			batchTransferVerifier,
			decimals: DECIMALS,
		});

		await encryptedVault_.waitForDeployment();


		// Deploy the EncryptedVaultBalances contract
		const encryptedVaultBalancesFactory = new EncryptedVaultBalances__factory({
			"contracts/libraries/BabyJubJub.sol:BabyJubJub": babyJubJub,
		});

		const encryptedVaultBalances_ = await encryptedVaultBalancesFactory.connect(owner).deploy();

		await encryptedVaultBalances_.waitForDeployment();

		// Deploy the EncryptedVaultManager contract with the encryptedVault, encryptedVaultBalances, and registrar addresses
		const encryptedVaultManagerFactory = new EncryptedVaultManager__factory({
			"contracts/libraries/BabyJubJub.sol:BabyJubJub": babyJubJub,
		});

		const encryptedVaultManager_ = await encryptedVaultManagerFactory.connect(owner).deploy(encryptedVault_.target, encryptedVaultBalances_.target, registrar_.target, vaultWithdrawalVerifier);

		await encryptedVaultManager_.waitForDeployment();

		// update the EncryptedVault contract with the encryptedVaultManager address
		await encryptedVault_.connect(owner).setVaultManager(encryptedVaultManager_.target);
		expect(await encryptedVault_.vaultManager()).to.equal(encryptedVaultManager_.target);

		// update the EncryptedVaultBalances contract with the encryptedVaultManager address
		await encryptedVaultBalances_.connect(owner).setVaultManager(encryptedVaultManager_.target);
		expect(await encryptedVaultBalances_.vaultManager()).to.equal(encryptedVaultManager_.target);
		

		registrar = registrar_;
		encryptedVault = encryptedVault_;
		encryptedVaultBalances = encryptedVaultBalances_;
		encryptedVaultManager = encryptedVaultManager_;
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
			let registrationCircuit: RegistrationCircuit;

			before(async () => {
				const circuit = await zkit.getCircuit("RegistrationCircuit");
				registrationCircuit = circuit as unknown as RegistrationCircuit;
			});

			it("users should be able to register properly", async () => {
				const network = await ethers.provider.getNetwork();
				const chainId = BigInt(network.chainId);

				for (const user of users.slice(0, 5)) {
					const registrationHash = user.genRegistrationHash(chainId);

					const input = {
						SenderPrivateKey: user.formattedPrivateKey,
						SenderPublicKey: user.publicKey,
						SenderAddress: BigInt(user.signer.address),
						ChainID: chainId,
						RegistrationHash: registrationHash,
					};

					const proof = await registrationCircuit.generateProof(input);
					const calldata = await registrationCircuit.generateCalldata(proof);
					// verify the proof
					await expect(registrationCircuit).to.verifyProof(proof);

					const tx = await registrar.connect(user.signer).register({
						proofPoints: calldata.proofPoints,
						publicSignals: calldata.publicSignals,
					});
					await tx.wait();

					// check if the user is registered
					expect(await registrar.isUserRegistered(user.signer.address)).to.be
						.true;

					// and the public key is set
					const publicKey = await registrar.getUserPublicKey(
						user.signer.address,
					);

					expect(publicKey).to.deep.equal(user.publicKey);
				}
			});
		});
	});

	describe("EncryptedVault - Converter", () => {
		let auditorPublicKey: [bigint, bigint];
		let funder: User;
		let receiver: User;
		let tokenId: number;
		let distributionAmountPublic: bigint;
		let distributionAmountEncrypted: bigint;
		let epochLength: bigint;

		const mockMintProof = {
			proofPoints: {
				a: ["0x0", "0x0"],
				b: [
					["0x0", "0x0"],
					["0x0", "0x0"],
				],
				c: ["0x0", "0x0"],
			},
			publicSignals: Array.from({ length: 24 }, () => 1n),
		};

		const mockTransferProof = {
			proofPoints: {
				a: ["0x0", "0x0"],
				b: [
					["0x0", "0x0"],
					["0x0", "0x0"],
				],
				c: ["0x0", "0x0"],
			},
			publicSignals: Array.from({ length: 32 }, () => 1n),
		};

		it("should initialize properly", async () => {
			expect(encryptedVault.target).to.not.be.null;
			expect(encryptedVault).to.not.be.null;

			// since eerc is standalone name and symbol should not be set
			expect(await encryptedVault.name()).to.equal("");
			expect(await encryptedVault.symbol()).to.equal("");

			// auditor key should not be set
			expect(await encryptedVault.isAuditorKeySet()).to.be.false;
		});

		describe("Auditor Key Set", () => {
			it("should revert if user try to call private burn without auditor key", async () => {
				await expect(
					encryptedVault.connect(users[0].signer).privateBurn(
						mockTransferProof as TransferProofStruct,
						Array.from({ length: 7 }, () => 1n),
					),
				).to.be.reverted;
			});

			it("should revert if user try to call private mint without auditor key", async () => {
				await expect(
					encryptedVault
						.connect(users[0].signer)
						.privateMint(
							users[0].signer.address,
							mockMintProof as MintProofStruct,
						),
				).to.be.reverted;
			});

			it("owner can set auditor key", async () => {
				const tx = await encryptedVault
					.connect(owner)
					.setAuditorPublicKey(owner.address);
				await tx.wait();

				expect(await encryptedVault.isAuditorKeySet()).to.be.true;

				auditorPublicKey = await encryptedVault.auditorPublicKey();
			});

			// this both should be here since we need to set auditor key first
			it("should revert if user try to call private burn in converter mode", async () => {
				await expect(
					encryptedVault.connect(users[0].signer).privateBurn(
						mockTransferProof as TransferProofStruct,
						Array.from({ length: 7 }, () => 1n),
					),
				).to.be.revertedWithCustomError(encryptedVault, "InvalidOperation");
			});

			it("should revert if user try to call private mint in converter mode", async () => {
				await expect(
					encryptedVault
						.connect(users[0].signer)
						.privateMint(
							users[0].signer.address,
							mockMintProof as MintProofStruct,
						),
				).to.be.revertedWithCustomError(encryptedVault, "InvalidOperation");
			});
		});

		describe("Depositing Tokens - Higher ERC20 Decimals (18)", () => {
			const mintAmount = 1000000000000000000000000000n;
			let userEncryptedBalance = 0n;

			it("should initialize user balance to 0", async () => {
				const ownerUser = users[0];
				const balance = await encryptedVault.balanceOf(
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
						.approve(encryptedVault.target, testCase.convertedAmount);

					const erc20BalanceBefore = await erc20.balanceOf(owner.address);

					// need to create a new pct for the amount
					const { ciphertext, nonce, authKey } = processPoseidonEncryption(
						[testCase.encryptedValue],
						ownerUser.publicKey,
					);

					await encryptedVault
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

					const balance = await encryptedVault.balanceOf(
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
				const depositAmount = 1_000_000_000_000_000_000_000_000_000n;

				// Mint some tokens to the owner
				await feeERC20.connect(owner).mint(owner.address, depositAmount * 10n);

				// Approve the deposit
				await feeERC20
					.connect(owner)
					.approve(encryptedVault.target, depositAmount);

				// Create the encrypted value
				const { ciphertext, nonce, authKey } = processPoseidonEncryption(
					[10n],
					ownerUser.publicKey,
				);

				await expect(
					encryptedVault
						.connect(owner)
						.deposit(depositAmount, feeERC20.target, [
							...ciphertext,
							...authKey,
							nonce,
						]),
				).to.be.revertedWithCustomError(encryptedVault, "TransferFailed");
			});
		});

		describe("Creating Vaults", () => {
			
			it("should default to no vault created", async () => {
				funder = users[0];
				receiver = users[1];
				tokenId = 1;

				const vaultId = await encryptedVaultManager.getVaultCreatedFor(funder.signer.address, receiver.signer.address, tokenId);
				expect(vaultId).to.equal(0);

				const allVaultsCreatedByFunder = await encryptedVaultManager.getVaultsCreatedBy(funder.signer.address);
				expect(allVaultsCreatedByFunder.length).to.equal(0);

				const allVaultsCreatedForReceiver = await encryptedVaultManager.getAllVaultsOwnedBy(receiver.signer.address);
				expect(allVaultsCreatedForReceiver.length).to.equal(0);
			});

			it("should create a vault for the user", async () => {
				distributionAmountPublic = 1000000000000000000000000000n;
				epochLength = 1n;

				const globalNonceBefore = await encryptedVaultManager.globalNonce();

				// generate the encrypted distribution amount using shared key of the funder and receiver
				const { 
					ciphertext: distributionAmtCiphertext,
					nonce: distributionAmtNonce,
					poseidonEncryptionKey: distributionAmtEncKey,
					authKey: distributionAmtAuthKey
				} = processPoseidonEncryptionEcdh(
					receiver.publicKey,
					funder.privateKey,
					distributionAmountPublic
				);

				const distributionAmountPCT: [bigint, bigint, bigint, bigint, bigint] = [
					distributionAmtCiphertext[0],
					distributionAmtCiphertext[1],
					distributionAmtCiphertext[2],
					distributionAmtCiphertext[3],
					distributionAmtNonce,
				];

				// create the vault
				await encryptedVaultManager.connect(funder.signer).createVault(
					receiver.signer.address,
					tokenId,
					distributionAmountPCT,
					epochLength
				);

				// check if the vault is created and check the vault settings
				const vaultId = await encryptedVaultManager.getVaultCreatedFor(funder.signer.address, receiver.signer.address, tokenId);
				expect(vaultId).to.not.equal(0);

				const vaultSettings = await encryptedVaultManager.getVault(vaultId);
				expect(vaultSettings.isActive).to.be.true;
				expect(vaultSettings.distributionAmountPCT).to.deep.equal(distributionAmountPCT);
				expect(vaultSettings.nonce).to.equal(globalNonceBefore);
				expect(vaultSettings.epochLength).to.equal(epochLength);
				expect(vaultSettings.tokenId).to.equal(tokenId);
				expect(vaultSettings.withdrawalsTotalPCT.length).to.equal(7);

				


				const decryptedDistributionAmount = processPoseidonDecryptionEcdh(
						funder.publicKey,
						receiver.privateKey,
						vaultSettings.distributionAmountPCT.slice(0,4),
						funder.publicKey,
						vaultSettings.distributionAmountPCT.slice(4)[0],
						1
					);
				expect(decryptedDistributionAmount).to.equal(distributionAmountPublic);

			});

			describe("Funding Vaults", () => {
				let funderStartingBalance: bigint;
				let fundingAmount: bigint;

				it("funder balance should be initialized properly", async ()=>{
					const balance = await encryptedVault.balanceOf(funder.signer.address, tokenId);

					const currentBalance = await getDecryptedBalance(
						funder.privateKey,
						balance.amountPCTs,
						balance.balancePCT,
						balance.eGCT
					);

					funderStartingBalance = currentBalance;
					fundingAmount = BigInt(Math.round(Number(currentBalance) * 0.9));

					


				});
				
				
				it("should fund the vault", async () => {
					const vaultId = await encryptedVaultManager.getVaultCreatedFor(funder.signer.address, receiver.signer.address, tokenId);

					
					const balance = await encryptedVault.balanceOf(funder.signer.address, tokenId);
					const funderEncryptedBalance = [...balance.eGCT.c1, ...balance.eGCT.c2];

					const { 
						proof: proof,
						senderBalancePCT: funderBalancePCT 
					} = await privateTransfer(
						funder,
						funderStartingBalance,
						receiver.publicKey,
						fundingAmount,
						funderEncryptedBalance,
						auditorPublicKey
					);

					const gasEstimate = await encryptedVaultManager.connect(funder.signer).fundVault.estimateGas(
						vaultId,
						tokenId,
						proof,
						funderBalancePCT
					);

					expect(
						await encryptedVaultManager.connect(funder.signer).fundVault(
							vaultId,
							tokenId,
							proof,
							funderBalancePCT
						)
					).to.be.not.reverted;

				});

				it("should update the vault balance properly", async() => {
					const vaultId = await encryptedVaultManager.getVaultCreatedFor(funder.signer.address, receiver.signer.address, tokenId);

					const vaultBalance = await encryptedVaultManager.getVaultBalance(vaultId);

					const vaultBalanceAfterFunding = await getDecryptedBalance(
						receiver.privateKey,
						vaultBalance.amountPCTs,
						vaultBalance.balancePCT,
						vaultBalance.eGCT
					);

					expect(vaultBalanceAfterFunding).to.equal(fundingAmount);
				
				});

				it("should update the funder balance properly", async() => {
					const funderBalance = await encryptedVault.balanceOf(funder.signer.address, tokenId);

					const funderBalanceAfterFunding = await getDecryptedBalance(
						funder.privateKey,
						funderBalance.amountPCTs,
						funderBalance.balancePCT,
						funderBalance.eGCT
					);	

					expect(funderBalanceAfterFunding).to.equal(funderStartingBalance - fundingAmount);
				});
			});

			describe ("Withdrawing from vaults", () => {
				let vaultId: bigint;
				let vaultBalanceBefore: bigint;
				let userBalanceBefore: bigint;
				let withdrawalsTotalBefore: bigint;
				let distributionAmountBefore: bigint;
				let currentBlock: bigint;

				
				it("should move the chain forward", async() => {
					/*
						Need to move the chain forward by 1 block. This is to ensure that there have been multiple epochs that have passed.

						Need to get the current block number and the start block.

						Need to calculate the number of epochs since the start block.
					*/
					const startBlock = await ethers.provider.getBlockNumber();
					const numBlocks = 15;

					for (let i = 0; i < numBlocks; i++) {
						await ethers.provider.send("evm_mine", []);
					}
					

					currentBlock = BigInt(await ethers.provider.getBlockNumber());

					expect(currentBlock).to.equal(startBlock + Number(numBlocks));
				});

				
				it("should get the vault settings, current vault balance, and user balance", async() => {
					/*
						Need to implement function to get the vault settings and the current vault balance.

						Then I will need to decrypt the vault balance, withdrawals total, and distribution amount.

						should store the "before" values for the vault balance and withdrawals total.

						should store the "before" values for the user balance.
					*/
					vaultId = await encryptedVaultManager.getVaultCreatedFor(funder.signer.address, receiver.signer.address, tokenId);
					
					const encryptedVaultBalance = await encryptedVaultManager.getVaultBalance(vaultId);
					vaultBalanceBefore = await getDecryptedBalance(
						receiver.privateKey,
						encryptedVaultBalance.amountPCTs,
						encryptedVaultBalance.balancePCT,
						encryptedVaultBalance.eGCT,

					);

					const userBalance = await encryptedVault.balanceOf(receiver.signer.address, tokenId);
					userBalanceBefore = await getDecryptedBalance(
						receiver.privateKey,
						userBalance.amountPCTs,
						userBalance.balancePCT,
						userBalance.eGCT,
					);

					const vaultSettings = await encryptedVaultManager.getVault(vaultId);
					expect(vaultSettings.withdrawalsTotalPCT[3]).to.equal(0);

					withdrawalsTotalBefore = 0n;

					distributionAmountBefore = BigInt(processPoseidonDecryptionEcdh(
						funder.publicKey,
						receiver.privateKey,
						vaultSettings.distributionAmountPCT.slice(0,4),
						funder.publicKey,
						vaultSettings.distributionAmountPCT.slice(4)[0],
						1
					));
				
				});
				
				
				it ("Should properly calculate amount to draw and withdraw from the vault", async() => {
					
					/*
						Need to get the current block number and the start block.

						Need to calculate the number of epochs since the start block.

						Need to calculate the amount to draw.

						The amount to draw must be less than or equal to the amount avaialble to be distributed.

					*/

					const vaultSettings = await encryptedVaultManager.getVault(vaultId);

					const distributionAmount = BigInt(
						processPoseidonDecryptionEcdh(
							funder.publicKey,
							receiver.privateKey,
							vaultSettings.distributionAmountPCT.slice(0,4),
							funder.publicKey,
							vaultSettings.distributionAmountPCT.slice(4)[0],
							1
						)
					);
					

					const {
						availableToDraw,
						remainder,
						epochsSinceStart
					} = await calculateMaxDraw(
						vaultSettings.startBlock,
						currentBlock,
						vaultSettings.epochLength,
						distributionAmount,
						BigInt(0)
					)

					const encryptedVaultBalance = await encryptedVaultManager.getVaultBalance(vaultId);
					const vaultBalanceNow = await getDecryptedBalance(
						receiver.privateKey,
						encryptedVaultBalance.amountPCTs,
						encryptedVaultBalance.balancePCT,
						encryptedVaultBalance.eGCT,

					);

					const {
						cipher: totalWithdrawalsCiphertext,
						random: totalWithdrawalsRandom
					} = encryptMessage(receiver.publicKey, withdrawalsTotalBefore);

					
					const withdrawalAmount = vaultBalanceNow / 2n;
					
					const {
						proof,
						senderBalancePCT
					} = await vaultWithdrawal(
						receiver,
						funder,
						BigInt(tokenId),
						withdrawalAmount,
						withdrawalsTotalBefore,
						[...totalWithdrawalsCiphertext[0], ...totalWithdrawalsCiphertext[1]],
						vaultBalanceNow,
						[...encryptedVaultBalance.eGCT.c1, ...encryptedVaultBalance.eGCT.c2],
						auditorPublicKey,
						distributionAmount,
						vaultSettings.distributionAmountPCT.slice(0,4),
						vaultSettings.distributionAmountPCT.slice(4)[0],
						vaultSettings.epochLength,
						vaultSettings.startBlock,
						currentBlock,
						epochsSinceStart,
						remainder
					);

					expect(
						await encryptedVaultManager.connect(receiver.signer).withdrawFromVault(
							vaultId,
							proof,
							senderBalancePCT
						)
					).to.be.not.reverted;

					
					// check the vault balance to make sure it was debited the corret amount.
					const encryptedVaultBalanceAfterWithdrawal = await encryptedVaultManager.getVaultBalance(vaultId);
					const vaultBalanceAfterWithdrawal = await getDecryptedBalance(
						receiver.privateKey,
						encryptedVaultBalanceAfterWithdrawal.amountPCTs,
						encryptedVaultBalanceAfterWithdrawal.balancePCT,
						encryptedVaultBalanceAfterWithdrawal.eGCT,
					);

					expect(vaultBalanceAfterWithdrawal).to.equal(vaultBalanceBefore - withdrawalAmount);
					
					//check the withdrawals total to make sure it now reflects the amount just withdrawn.
					const vaultSettingsAfterWithdrawal = await encryptedVaultManager.getVault(vaultId);
					const withdrawalsTotalAfterWithdrawal = await decryptPCT(receiver.privateKey, vaultSettingsAfterWithdrawal.withdrawalsTotalPCT);
					expect(withdrawalsTotalAfterWithdrawal[0]).to.equal(withdrawalsTotalBefore + withdrawalAmount);
					
					//check the user's balance to make sure it was credited with the amount from the withdrawal
					const userBalanceAfterWithdrawal = await encryptedVault.balanceOf(receiver.signer.address, tokenId);
					const userBalanceAfterWithdrawalDecrypted = await getDecryptedBalance(
						receiver.privateKey,
						userBalanceAfterWithdrawal.amountPCTs,
						userBalanceAfterWithdrawal.balancePCT,
						userBalanceAfterWithdrawal.eGCT,
					);

					expect(userBalanceAfterWithdrawalDecrypted).to.equal(userBalanceBefore + withdrawalAmount);

				});

				it("should allow a user to performa a private transfer using funds withdrawn from the vault", async() => {
					/*
						Just need to process a withdrawal that is equal to or less than t
					*/
				});
				
				it("should not allow a user to withdraw more than the available amount", async() => {
					/*
						Need to write a test that will attempt to withdraw more than the avaialble amount.
					*/
				});

				it("should allow a relayer to process a withdrawal for the receiver", async() => {
					/*
						need to write a test that will process a withdrawal for the receiver. that is sent by a different address.
					*/
				});
			});

			describe("Transfer")
		});
	});
});