import { exec } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import util from "node:util";
import type { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/dist/src/signer-with-address";
import { RegistrationVerifier__factory } from "../typechain-types/factories/contracts/verifiers";

const execAsync = util.promisify(exec);

export const deployVerifiers = async (signer: SignerWithAddress) => {
	const registrationVerifierFactory = new RegistrationVerifier__factory(signer);
	const registrationVerifier = await registrationVerifierFactory.deploy();
	await registrationVerifier.waitForDeployment();

	return {
		registrationVerifier: registrationVerifier.target.toString(),
	};
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
	input: string,
): Promise<string[]> => {
	const outputPath = path.join(__dirname, `${type}.output.json`);

	let pkPath = "";
	let csPath = "";

	switch (type) {
		case "REGISTER":
			pkPath = path.join(__dirname, "../", "build", "register.pk");
			csPath = path.join(__dirname, "../", "build", "register.r1cs");
			break;
		default:
			break;
	}

	const executableName = "encryptedERC";
	const executable = path.join(__dirname, "../", "zk", "build", executableName);

	const cmd = `${executable} --operation ${type} --input '${input}' --pk ${pkPath} --cs ${csPath} --output ${outputPath}`;

	const { stderr: err, stdout } = await execAsync(cmd);
	console.log(stdout);

	if (err) throw new Error(err);

	const output = fs.readFileSync(outputPath, "utf-8");
	const { proof } = JSON.parse(output);

	fs.unlinkSync(outputPath);

	return proof;
};
