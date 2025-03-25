<div align="center">
  <img src="images/banner.png">
</div>

---

# Encrypted ERC-20 Protocol

The Encrypted ERC-20 (eERC) standard enables secure and confidential token transfers on Avalanche blockchains. Leveraging zk-SNARKs and partially homomorphic encryption, the eERC protocol offers robust privacy without requiring protocol-level modifications or off-chain intermediaries.

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

   On arm64:

   ```sh
   go build -o ./build/encryptedERC
   ```

### Run Tests/Coverage

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
|      setAuditorPublicKey  ·              -  ·            -  ·        103,800  ·             4  ·           △  │
····························|·················|···············|·················|················|···············
|      setTokenBlacklist    ·              -  ·            -  ·         46,443  ·             1  ·           △  │
····························|·················|···············|·················|················|···············
|      transfer             ·        929,453  ·      929,477  ·        929,469  ·             6  ·        0.02  │
····························|·················|···············|·················|················|···············
|      withdraw             ·        764,964  ·      820,100  ·        786,662  ·             6  ·        0.02  │
····························|·················|···············|·················|················|···············
|  FeeERC20                 ·                                                                                   │
····························|·················|···············|·················|················|···············
|      approve              ·              -  ·            -  ·         46,335  ·             1  ·           △  │
····························|·················|···············|·················|················|···············
|      mint                 ·              -  ·            -  ·         68,508  ·             1  ·           △  │
····························|·················|···············|·················|················|···············
|  Registrar                ·                                                                                   │
····························|·················|···············|·················|················|···············
|      register             ·        315,948  ·      316,008  ·        315,985  ·            20  ·        0.01  │
····························|·················|···············|·················|················|···············
|  SimpleERC20              ·                                                                                   │
····························|·················|···············|·················|················|···············
|      approve              ·         46,323  ·       46,383  ·         46,350  ·            16  ·           △  │
····························|·················|···············|·················|················|···············
|      mint                 ·         68,433  ·       68,457  ·         68,441  ·             6  ·           △  │
····························|·················|···············|·················|················|···············
|  Deployments                                ·                                 ·  % of limit    ·              │
····························|·················|···············|·················|················|···············
|  BabyJubJub               ·              -  ·            -  ·        447,616  ·         1.5 %  ·        0.01  │
····························|·················|···············|·················|················|···············
|  EncryptedERC             ·      3,356,864  ·    3,381,990  ·      3,369,427  ·        11.2 %  ·        0.07  │
····························|·················|···············|·················|················|···············
|  FeeERC20                 ·              -  ·            -  ·        658,116  ·         2.2 %  ·        0.01  │
····························|·················|···············|·················|················|···············
|  MintVerifier             ·              -  ·            -  ·      1,769,766  ·         5.9 %  ·        0.04  │
····························|·················|···············|·················|················|···············
|  Registrar                ·              -  ·            -  ·        407,830  ·         1.4 %  ·        0.01  │
····························|·················|···············|·················|················|···············
|  RegistrationVerifier     ·              -  ·            -  ·      1,213,044  ·           4 %  ·        0.03  │
····························|·················|···············|·················|················|···············
|  SimpleERC20              ·        557,086  ·      557,146  ·        557,101  ·         1.9 %  ·        0.01  │
····························|·················|···············|·················|················|···············
|  TransferVerifier         ·              -  ·            -  ·      2,004,265  ·         6.7 %  ·        0.04  │
····························|·················|···············|·················|················|···············
|  WithdrawVerifier         ·              -  ·            -  ·      1,534,779  ·         5.1 %  ·        0.03  │
····························|·················|···············|·················|················|···············
|  Key                                                                                                          │
·················································································································
|  ◯  Execution gas for this method does not include intrinsic gas overhead                                     │
·················································································································
|  △  Cost was non-zero but below the precision setting for the currency display (see options)                  │
·················································································································
|  Toolchain:  hardhat                                                                                          │
·················································································································
```

### ⏱️ Circuit Benchmarks for Proof Generation

Tested on M3 Pro CPU:

| **Operation**    | **Proving Time** |
| ---------------- | ---------------- |
| Registration     | 71 ms            |
| Private Mint     | 359 ms           |
| Private Burn     | 360 ms           |
| Private Transfer | 606 ms           |
