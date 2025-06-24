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
//import { EmployeeDataProofStruct } from "../typechain-types/contracts/Payroll.sol";
import type { PayrollManager } from "../typechain-types/contracts/Payroll.sol";
import type {
	RegisterProofStruct,
	Registrar,
} from "../typechain-types/contracts/Registrar";
import {
	EncryptedERC__factory,
	Registrar__factory,
} from "../typechain-types/factories/contracts";
import {
	PayrollManager__factory,
} from "../typechain-types/factories/contracts/Payroll.sol";
import {
	decryptPCT,
	deployLibrary,
	deployVerifiers,
	getDecryptedBalance,
	privateBurn,
	privateMint,
	privateTransfer,
} from "./helpers";
import { User } from "./user";
import { encryptMessageEcdh, decryptMessageEcdh } from "../src/ecdh/ecdh";
import { processPoseidonEncryption, processPoseidonDecryption, processPoseidonEncryptionEcdh, processPoseidonDecryptionEcdh, processPoseidonDecryptionEcdhSender, stringToBigInt, randomNonce } from "../src/poseidon/poseidon";
import { genRandomBabyJubValue } from "maci-crypto";
import { 
    claimBonus, 
    analyzeCircuitOutput,
    generateBonusIdPCTForNewBonus,
    generateEncryptedBonusIdPCTForClaim,
    generateJubKeysFromPrivateKey
 } from "./payroll_helpers";
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
	let payrollManager: PayrollManager;

	const deployFixture = async () => {
		signers = await ethers.getSigners();
		owner = signers[0];

		const {
			registrationVerifier,
			mintVerifier,
			withdrawVerifier,
			transferVerifier,
			batchTransferVerifier,
			payrollVerifier
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

		const payrollManagerFactory = new PayrollManager__factory(owner);
		const payrollManager_ = await payrollManagerFactory.connect(owner).deploy(registrar_.target, payrollVerifier);
		await payrollManager_.waitForDeployment();

		registrar = registrar_;
		encryptedERC = encryptedERC_;
		payrollManager = payrollManager_;
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

    describe("Encryption and Decryption using AES", () => {
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
    });

    describe("Encryption and Decryption using PCT", () => {
        it("should encrypt and decrypt message properly PCT", async () => {
            const messageInput = "Hello World";

            const sender = users[0];
            const receiver = users[1];

            const {ciphertext, nonce, poseidonEncryptionKey, authKey} = processPoseidonEncryptionEcdh(
                receiver.publicKey,
                sender.privateKey,
                messageInput
            );

            console.log("Ciphertext:", ciphertext);
            console.log("Auth Key:", authKey);
            console.log("Nonce:", nonce);
            
            const decryptedMessage = processPoseidonDecryptionEcdh(
                sender.publicKey,
                receiver.privateKey,
                ciphertext,
                authKey,
                nonce,
                1
            );

            console.log("Decrypted Message Receiver:", decryptedMessage);
            expect(decryptedMessage).to.equal(messageInput);

            const decryptedMessageSender = processPoseidonDecryptionEcdhSender(
                receiver.publicKey,
                sender.privateKey,
                ciphertext,
                authKey,
                nonce,
                1
            );

            console.log("Decrypted Message Sender:", decryptedMessageSender);
            expect(decryptedMessageSender).to.equal(messageInput);

        });
    });

    describe("Payroll Manager", () => {
        let employee: User;
        let business: User;
        let bonusPrivKey: bigint;
        let bonusPubKey: bigint[];
        let employeeName: string;
        let employeeId: bigint;
        let bonusId: bigint;
        let bonusIndex: bigint = 0n;
        // let validProof: EmployeeDataProofStruct;
        let bonusData: PayrollManager.BonusStructOutput;

        it("should register employee properly", async () => {
            business = users[0];
            employee = users[1];

            // employee data
            employeeId = 1234n;
            employeeName = "John Doe";

            // generate PCT for employeeId with employee public key
            const {
                ciphertext: employeeIdCiphertext,
                nonce: employeeIdNonce,
                authKey: employeeIdAuthKey,
                encRandom: employeeIdEncRandom
            } = processPoseidonEncryption(
                [employeeId],
                employee.publicKey
            );
            const employeeIdPCT = [
                ...employeeIdCiphertext,
                ...employeeIdAuthKey,
                employeeIdNonce
            ]

            // generate PCT for employeeName with shared key
            const {
                ciphertext: employeeNameCiphertext,
                nonce: employeeNameNonce,
                authKey: employeeNameAuthKey,
                poseidonEncryptionKey: businessPublicKey
            } = processPoseidonEncryptionEcdh(
                employee.publicKey,
                business.privateKey,
                employeeName
            );
            const employeeNamePCT = [
                ...employeeNameCiphertext,
                employeeNameNonce
            ];

            // create the new employee data
            expect(
                await payrollManager.connect(business.signer)
                .createNewEmployeeData(
                    employee.signer.address,
                    employeeNamePCT as [bigint, bigint, bigint, bigint, bigint],
                    employeeIdPCT
                )
            ).to.be.not.reverted;

            const employeeData = await payrollManager.fetchPrivateEmployeeData(employee.signer.address, business.signer.address);
        });

        it("should fetch employee data properly", async () => {
             
            // fetch the employee data from the contract
             const employeeData = await payrollManager.fetchPrivateEmployeeData(employee.signer.address, business.signer.address);
             console.log("Employee Data:", employeeData);
 
             console.log("Employee ID PCT:", employeeData.employeeIdPCT);
 
             // check that the employee data is correct
             const decryptedEmployeeId = processPoseidonDecryption(
                 employeeData.employeeIdPCT.slice(0,4),
                 employeeData.employeeIdPCT.slice(4,6),
                 employeeData.employeeIdPCT[6], 
                 employee.privateKey,
                 1
             );
             expect(decryptedEmployeeId[0]).to.equal(employeeId);
 
             const decryptedEmployeeName = processPoseidonDecryptionEcdh(
                  business.publicKey,
                  employee.privateKey,
                  employeeData.namePCT.slice(0,4),
                  business.publicKey,
                  employeeData.namePCT.slice(4)[0],
                  1
             );
             expect(decryptedEmployeeName).to.equal(employeeName);
 
        });

        it("should issue bonus properly", async () => {
            const bonusAmount = 1000n;
            bonusPrivKey = users[2].privateKey;
            bonusPubKey = users[2].publicKey;
            bonusId = genRandomBabyJubValue() / 10n

            // Bonus amount encrypted with employee public key
            const {
                ciphertext: bonusAmountCipherText,
                authKey: bonusAmountAuthKey,
                nonce: bonusAmountNonce,
                encRandom: bonusAmountEncRandom
            } = processPoseidonEncryption(
                [bonusAmount],
                employee.publicKey
            );
            const bonusAmountPCT = [
                ...bonusAmountCipherText,
                ...bonusAmountAuthKey,
                bonusAmountNonce
            ];

            // Bonus sk encrypted with employee public key 
            const {
                ciphertext: bonusSkCipherText,
                authKey: bonusSkAuthKey,
                nonce: bonusSkNonce,
                encRandom: bonusSkEncRandom
            } = processPoseidonEncryption(
                [bonusPrivKey],
                employee.publicKey
            );
            const bonusSkPCT = [
                ...bonusSkCipherText,
                ...bonusSkAuthKey,
                bonusSkNonce
            ];

            // Bonus id encrypted with bonus public key
            const lastBonusNonce = await payrollManager
                .connect(business.signer)
                .fetchLastBonusNonce(business.signer.address, employee.signer.address)
            

            const {
                publicKey: _,
                formattedPrivateKey: bonusFormattedPrivKey
            } = await generateJubKeysFromPrivateKey(bonusPrivKey);

            const {
                ciphertext: bonusIdCipherText,
                authKey: bonusIdAuthKey,
                nonce: bonusIdNonce,
                encRandom: bonusIdEncRandom
            } = await generateBonusIdPCTForNewBonus(
                bonusId,
                bonusFormattedPrivKey,
                bonusPubKey,
                lastBonusNonce,
            )
            
            const bonusIdPCT = [
                ...bonusIdCipherText,
                ...bonusIdAuthKey,
                bonusIdNonce
            ];

            // Issue bonus to employee
            const tx = await payrollManager.connect(business.signer)
                .issueBonus(
                    employee.signer.address,
                    bonusAmountPCT,
                    bonusIdPCT  
                );
            const receipt = await tx.wait();
            const blockNumber = receipt?.blockNumber || await ethers.provider.getBlockNumber();

            // Fetch bonus data
            const [bonusData_, bonusIndex] = await payrollManager.connect(employee.signer).fetchFirstUnclaimedBonuses(business.signer.address);
            bonusData = bonusData_
            console.log("Bonus Data:", bonusData);
            // Decrypt Bonus Amount
            const decryptedBonusAmount = processPoseidonDecryption(
                bonusData.amountPCT.slice(0,4),
                bonusData.amountPCT.slice(4,6),
                bonusData.amountPCT[6],
                employee.privateKey,
                1
            );
            console.log("Decrypted Bonus Amount:", decryptedBonusAmount);
            expect(decryptedBonusAmount[0]).to.equal(bonusAmount);

            /*
            // Decrypt Bonus PrivKey
            const decryptedBonusSk = processPoseidonDecryption(
                bonusData.bonusSkPCT.slice(0,4),
                bonusData.bonusSkPCT.slice(4,6),
                bonusData.bonusSkPCT[6],
                employee.privateKey,
                1
            );
            console.log("Decrypted Bonus Sk:", decryptedBonusSk);
            console.log("Bonus PrivKey:", bonusPrivKey);
            expect(decryptedBonusSk[0]).to.equal(bonusPrivKey);
            */

            // Decrypt bonus ID
            const decryptedBonusId = processPoseidonDecryption(
                bonusData.bonusIdPCT.slice(0,4),    
                bonusData.bonusIdPCT.slice(4,6),
                bonusData.bonusIdPCT[6],
                bonusPrivKey,
                1
            );
            console.log("Decrypted Bonus Id:", decryptedBonusId);
            expect(decryptedBonusId[0]).to.equal(bonusId);

            // Check nonceUsed instead of blockNumber
            expect(bonusData.nonceUsed).to.be.greaterThan(0);
        });

        it("should claim bonus properly", async () => {
            
            // Bonus id encrypted with bonus public key
            const lastBonusNonce = await payrollManager
                .connect(employee.signer)
                .fetchLastBonusNonce(business.signer.address, employee.signer.address)
            
            const {
                proof: claimCalldata,
                inputValues: inputVals
            } = await claimBonus(
                employee,
                business.publicKey,
                bonusId,
                employeeId,
                employeeName,
                bonusPrivKey,
                bonusData.bonusIdPCT,
                lastBonusNonce
            )

            // Analyze the circuit output separately
            const { fieldOrder, fieldMapping } = analyzeCircuitOutput(
                inputVals,
                claimCalldata.publicSignals
            );

            console.log("Claim Public Signals:", claimCalldata.publicSignals.map((x) => BigInt(x)));
            console.log("Field Order:", fieldOrder);
            console.log("Field Mapping:", fieldMapping);

            //console.log("Bonus Data:", bonusData);
            

            try {
                const tx = await payrollManager
                    .connect(employee.signer)
                    .claimBonus(
                        business.signer.address,
                        claimCalldata,
                        bonusIndex
                    );
                await tx.wait();
            } catch (error) {
                console.error("Claim bonus error:", error);
                throw error;
            }
        });

        
        
    })
})