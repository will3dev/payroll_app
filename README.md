<div align="center">
  <img src="images/banner.png">
</div>

---

# Encrypted ERC-20 Protocol

The Encrypted ERC-20 (eERC) standard enables secure and confidential token transfers on Avalanche blockchains. Leveraging zk-SNARKs and partially homomorphic encryption, the eERC protocol offers robust privacy without requiring protocol-level modifications or off-chain intermediaries. 

AvaCloud API documentation can be found [here](https://docs.avacloud.io/encrypted-erc/getting-started/what-is-encrypted-erc).

## Key features

- Confidential Transactions: User balances and transaction amounts remain completely hidden, ensuring financial privacy.
- Large Integers: Efficiently handles token amounts up to 128 bits (2^128), accommodating substantial financial transactions.
- Client-Side Operations: Users retain control, performing encryption, decryption, and zk-proof generation directly on their own devices.
- Fully On-chain Nature: Operates entirely on-chain without the need for relayers or off-chain actors.
- Built-in Compliance: Supports external auditors, ensuring regulatory compliance.

## File structure

- [contracts](#contracts) Smart contract source files
- [scripts](#scripts) Utility and deployment scripts
- [src](#src) Encryption utilities for TypeScript
- [tests](#tests) Test scripts and helpers
- [zk](#zk) Gnark-based implementations of zero-knowledge proof components

## Getting Started

### Prerequisites

You need following dependencies for setup:

- `NodeJS >= v16.x `
- `Golang >= 1.23.x `

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/ava-labs/EncryptedERC.git
   ```
2. Install NPM packages

   ```sh
   npm install
   ```
   Note: This command will run a bash script to compile gnark's circuits, if this does not work:
   In [zk](#zk) directory run the following command to build manually:
   ```sh
   make
   ```
   or

   ```sh
   go build -o ./build/encryptedERC ./cmd/
   ```
3. Compile the contracts

   ```sh
   npx hardhat compile
   ```
## Deployment (Local)

### Standalone
The Standalone version lets users create entirely new private ERC-20 tokens with built-in privacy, supporting confidential minting and burning.

1. Start the local node
```bash
npx hardhat node
```

2. Deploy the contract
```bash
npx hardhat run scripts/deploy-standalone.ts --network localhost
```

Refer to the [scripts/deploy-standalone.ts](scripts/deploy-standalone.ts) script for deployment examples.

### Converter
The Converter version adds privacy features to existing ERC-20 tokens, enabling users to convert standard ERC-20 tokens to private ones and switch between public and private states through deposit and withdrawal functions.

1. Start the local node
```bash
npx hardhat node
```

2. Deploy the contract
```bash
npx hardhat run scripts/deploy-converter.ts --network localhost
```

Refer to the [scripts/deploy-converter.ts](scripts/deploy-converter.ts) script for deployment examples.

## Run Tests/Coverage

Contract tests:

```
npx hardhat coverage
```

## 📊 Performance Overview

### ⛽ Avg. On-Chain Gas Costs (C-Chain Mainnet)

```
·················································································································
|  Solidity and Network Configuration                                                                           │
····························|·················|···············|·················|································
|  Solidity: 0.8.27         ·  Optim: true    ·  Runs: 200    ·  viaIR: false   ·     Block: 30,000,000 gas     │
····························|·················|···············|·················|································
|  Network: AVALANCHE       ·  L1: 1 gwei                     ·                 ·        21.91 usd/avax         │
····························|·················|···············|·················|················|···············
|  Contracts / Methods      ·  Min            ·  Max          ·  Avg            ·  # calls       ·  usd (avg)   │
····························|·················|···············|·················|················|···············
|  EncryptedERC             ·                                                                                   │
····························|·················|···············|·················|················|···············
|      deposit              ·         71,842  ·      841,926  ·        565,079  ·            16  ·        0.01  │
····························|·················|···············|·················|················|···············
|      privateBurn          ·        872,327  ·    1,209,788  ·      1,010,477  ·             4  ·        0.02  │
····························|·················|···············|·················|················|···············
|      privateMint          ·        704,167  ·      752,463  ·        713,839  ·            10  ·        0.02  │
····························|·················|···············|·················|················|···············
|      setAuditorPublicKey  ·              -  ·            -  ·        103,800  ·             4  ·           -  │
····························|·················|···············|·················|················|···············
|      setTokenBlacklist    ·              -  ·            -  ·         46,443  ·             1  ·           -  │
····························|·················|···············|·················|················|···············
|      transfer             ·        929,453  ·      929,477  ·        929,469  ·             6  ·        0.02  │
····························|·················|···············|·················|················|···············
|      withdraw             ·        764,964  ·      820,100  ·        786,662  ·             6  ·        0.02  │
····························|·················|···············|·················|················|···············
|      register             ·        315,948  ·      316,008  ·        315,985  ·            20  ·        0.01  │
····························|·················|···············|·················|················|···············
```

### ⏱️ Circuit Benchmarks for Proof Generation

Tested on M3 Pro CPU:

| **Operation**    | **Proving Time** |
| ---------------- | ---------------- |
| Registration     | 71 ms            |
| Private Mint     | 359 ms           |
| Private Burn     | 360 ms           |
| Private Transfer | 606 ms           |


