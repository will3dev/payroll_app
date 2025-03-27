import type { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import {
	X_RegisterVerifier__factory,
	X_MintVerifier__factory,
	X_WithdrawVerifier__factory,
	X_TransferVerifier__factory,
} from "../typechain-types";

export const deployProductionVerifiers = async (
	signer: SignerWithAddress,
): Promise<{
	registrationVerifier: string;
	mintVerifier: string;
	withdrawVerifier: string;
	transferVerifier: string;
}> => {
	const registrationVerifierFactory = new X_RegisterVerifier__factory(signer);
	const registrationVerifier = await registrationVerifierFactory.deploy();
	await registrationVerifier.waitForDeployment();

	const mintVerifierFactory = new X_MintVerifier__factory(signer);
	const mintVerifier = await mintVerifierFactory.deploy();
	await mintVerifier.waitForDeployment();

	const withdrawVerifierFactory = new X_WithdrawVerifier__factory(signer);
	const withdrawVerifier = await withdrawVerifierFactory.deploy();
	await withdrawVerifier.waitForDeployment();

	const transferVerifierFactory = new X_TransferVerifier__factory(signer);
	const transferVerifier = await transferVerifierFactory.deploy();
	await transferVerifier.waitForDeployment();

	return {
		registrationVerifier: registrationVerifier.target.toString(),
		mintVerifier: mintVerifier.target.toString(),
		withdrawVerifier: withdrawVerifier.target.toString(),
		transferVerifier: transferVerifier.target.toString(),
	};
};
