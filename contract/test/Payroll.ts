import type { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";
import { expect } from "chai";
import { ethers, zkit } from "hardhat";
import type {
	CalldataMintCircuitGroth16,
	CalldataRegistrationCircuitGroth16,
	RegistrationCircuit,
} from "../generated-types/zkit";
import { BN254_SCALAR_FIELD } from "../src/constants";
import { decryptPoint } from "../src/jub/jub";
import type {
	EncryptedERC,
	MintProofStruct,
	TransferProofStruct,
} from "../typechain-types/contracts/EncryptedERC";
import type {
	RegisterProofStruct,
	Registrar,
} from "../typechain-types/contracts/Registrar";
import {
	EncryptedERC__factory,
	Registrar__factory,
} from "../typechain-types/factories/contracts";
import {
	decryptPCT,
	deployLibrary,
	deployVerifiers,
	getDecryptedBalance,
	privateBurn,
	privateMint,
	privateTransfer,
	batchTransfer,
} from "./helpers";
import { User } from "./user";
import { encryptMessageEcdh, decryptMessageEcdh } from "../src/ecdh/ecdh";

const DECIMALS = 2;


/* 

Need to set up and deploy the payroll contract and the eERC contracts
Will need to have useres register
Will need to add a function to generate the encrypted 

*/

describe("Payroll", () => {
    let registrar: Registrar;
	let users: User[];
	let signers: SignerWithAddress[];
	let owner: SignerWithAddress;
	let encryptedERC: EncryptedERC;

	const deployFixture = async () => {
		signers = await ethers.getSigners();
		owner = signers[0];

		const {
			registrationVerifier,
			mintVerifier,
			withdrawVerifier,
			transferVerifier,
			batchTransferVerifier,
		} = await deployVerifiers(owner, false);
		const babyJubJub = await deployLibrary(owner);

		const registrarFactory = new Registrar__factory(owner);
		const registrar_ = await registrarFactory
			.connect(owner)
			.deploy(registrationVerifier);

		await registrar_.waitForDeployment();

		const encryptedERCFactory = new EncryptedERC__factory({
			"contracts/libraries/BabyJubJub.sol:BabyJubJub": babyJubJub,
		});

		console.log("Batch transfer verifier:", batchTransferVerifier);

		const encryptedERC_ = await encryptedERCFactory.connect(owner).deploy({
			registrar: registrar_.target,
			isConverter: false,
			name: "Test",
			symbol: "TEST",
			mintVerifier,
			withdrawVerifier,
			transferVerifier,
			decimals: DECIMALS,
			batchTransferVerifier
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
			let registrationCircuit: RegistrationCircuit;
			let validProof: CalldataRegistrationCircuitGroth16;
			const mockRegisterProof = {
				proofPoints: {
					a: ["0x0", "0x0"],
					b: [
						["0x0", "0x0"],
						["0x0", "0x0"],
					],
					c: ["0x0", "0x0"],
				},
				publicSignals: Array.from({ length: 5 }, () => 1n), // index 3 is chain id
			};

			before(async () => {
				const circuit = await zkit.getCircuit("RegistrationCircuit");
				registrationCircuit = circuit as unknown as RegistrationCircuit;
			});

			it("should revert if chain id is not matching", async () => {
				const sender = users[0];
				const publicSignals = [...mockRegisterProof.publicSignals];

				// index 2 is for account address
				publicSignals[2] = BigInt(sender.signer.address);
				// index 3 is for chain id
				publicSignals[3] = 100n;

				await expect(
					registrar.connect(sender.signer).register({
						proofPoints: mockRegisterProof.proofPoints,
						publicSignals: publicSignals,
					} as RegisterProofStruct),
				).to.be.revertedWithCustomError(registrar, "InvalidChainId");
			});

			it("should revert if registration hash is not valid", async () => {
				const sender = users[0];
				const publicSignals = [...mockRegisterProof.publicSignals];
				const chainId = await ethers.provider
					.getNetwork()
					.then((network) => network.chainId);

				// index 2 is for account address
				publicSignals[2] = BigInt(sender.signer.address);
				// index 3 is for chain id
				publicSignals[3] = chainId;
				// index 4 is for registration hash
				publicSignals[4] = BN254_SCALAR_FIELD + 1n;

				await expect(
					registrar.connect(sender.signer).register({
						proofPoints: mockRegisterProof.proofPoints,
						publicSignals: publicSignals,
					} as RegisterProofStruct),
				).to.be.revertedWithCustomError(registrar, "InvalidRegistrationHash");
			});

			it("users should be able to register properly", async () => {
				const chainId = await ethers.provider
					.getNetwork()
					.then((network) => network.chainId);

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

					expect(await registrar.isUserRegistered(user.signer.address)).to.be.true;
					// and the public key is set
					const contractPublicKey = await registrar.getUserPublicKey(
						user.signer.address,
					);
					expect(contractPublicKey).to.deep.equal(user.publicKey);

					// and the registration hash is set
					const contractRegistrationHash = await registrar.isRegistered(
						input.RegistrationHash,
					);
					expect(contractRegistrationHash).to.be.true;

					validProof = calldata;
				}
			});

            it("already registered user can not register again", async () => {
				const alreadyRegisteredUser = users[4];

				await expect(
					registrar.connect(alreadyRegisteredUser.signer).register({
						proofPoints: validProof.proofPoints,
						publicSignals: validProof.publicSignals,
					}),
				).to.be.revertedWithCustomError(registrar, "UserAlreadyRegistered");
			});

			it("should revert if sender is not matching", async () => {
				// valid proof is for user[4] but we are using user[0]
				const sender = users[0];

				await expect(
					registrar.connect(sender.signer).register({
						proofPoints: validProof.proofPoints,
						publicSignals: validProof.publicSignals,
					} as RegisterProofStruct),
				).to.be.revertedWithCustomError(registrar, "InvalidSender");
			});

			it("should revert if proof is not valid", async () => {
				const user = new User(signers[5]);
				const chainId = await ethers.provider
					.getNetwork()
					.then((network) => network.chainId);

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

				await expect(
					registrar.connect(user.signer).register({
						proofPoints: mockRegisterProof.proofPoints,
						publicSignals: calldata.publicSignals,
					} as RegisterProofStruct),
				).to.be.revertedWithCustomError(registrar, "InvalidProof");
			});
		});
	});

    describe("Encryption and Decryption", () => {
        it("should encrypt and decrypt message properly", async () => {
            const messageInput = "Hello World";

            const sender = users[0];
            const receiver = users[1];

            const senderPublicKeyTuple: [bigint, bigint] = [
                BigInt(sender.publicKey[0]),
                BigInt(sender.publicKey[1])
            ]

            const receiverPublicKeyTuple: [bigint, bigint] = [
                BigInt(receiver.publicKey[0]),
                BigInt(receiver.publicKey[1])
            ]
            
            const encryptedMessage = encryptMessageEcdh(
                receiverPublicKeyTuple, // need to pass in the public key of the receiver
                sender.privateKey,
                messageInput
            );

            const decryptedMessage = decryptMessageEcdh(
                senderPublicKeyTuple, // need to pass in the public key of the sender
                receiver.privateKey,
                encryptedMessage
            )
            console.log("Encrypted Message:", encryptedMessage);
            console.log("Decrypted Message:", decryptedMessage);
            expect(decryptedMessage).to.equal(messageInput);
        });




        
    })



})