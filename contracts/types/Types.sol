// (c) 2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.27;

struct Point {
    uint256 x;
    uint256 y;
}

struct CreateEncryptedERCParams {
    address registrar;
    bool isConverter;
    string name;
    string symbol;
    uint8 decimals;
    // verifiers
    address mintVerifier;
    address withdrawVerifier;
    address transferVerifier;
}

struct AmountPCT {
    uint256[7] pct;
    uint256 index;
}

struct EncryptedBalance {
    EGCT eGCT;
    mapping(uint256 index => BalanceHistory history) balanceList;
    uint256 nonce;
    uint256 transactionIndex;
    uint256[7] balancePCT; // user balance pcts
    AmountPCT[] amountPCTs; // user amount pcts
}

struct BalanceHistory {
    uint256 index;
    bool isValid;
}

struct EGCT {
    Point c1;
    Point c2;
}
