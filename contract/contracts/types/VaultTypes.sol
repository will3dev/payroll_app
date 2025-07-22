// (c) 2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.27;

import { ProofPoints, EGCT } from "./Types.sol";

struct VaultSettings {
    bool isActive;
    uint256[5] distributionAmountPCT; // encrypted with shared key
    uint256 nonce; // nonce for the vault
    uint256 epochLength; // number of blocks in each epoch
    uint256 startBlock; // block number when the vault was created 
    uint256 tokenId; // the ID of the token that this vault is associated with
    uint256[7] withdrawalsTotalPCT; // the PCT of the current total of withdrawals
    EGCT withdrawalsTotalEGCT;
}


struct VaultWithdrawalProof {
    ProofPoints proofPoints;
    uint256[50] publicSignals;
}

struct VaultFundProof {
    ProofPoints proofPoints;
    uint256[16] publicSignals;
}
