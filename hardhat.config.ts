import type { HardhatUserConfig } from "hardhat/config";
import "@typechain/hardhat";
import "solidity-coverage";
import "hardhat-gas-reporter";
import "@nomicfoundation/hardhat-chai-matchers";
import "@nomicfoundation/hardhat-ethers";

import dotenv from "dotenv";
dotenv.config();

const RPC_URL = process.env.RPC_URL || "https://api.avax.network/ext/bc/C/rpc";

const config: HardhatUserConfig = {
	solidity: {
		version: "0.8.27",
		settings: {
			optimizer: {
				enabled: true,
				runs: 200,
			},
		},
	},
	networks: {
		hardhat: {
			chainId: 43114,
			forking: {
				url: RPC_URL,
				blockNumber: 59121339,
				enabled: !!process.env.FORKING,
			},
		},
	},
	gasReporter: {
		enabled: !!process.env.REPORT_GAS,
		currency: "USD",
		coinmarketcap: process.env.COINMARKETCAP_API_KEY,
		excludeContracts: ["contracts/mocks/"],
		outputFile: "gas-report.txt",
		L1: "avalanche",
		showMethodSig: true,
	},
};

export default config;
