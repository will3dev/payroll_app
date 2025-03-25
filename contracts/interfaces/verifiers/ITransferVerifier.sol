// (c) 2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.27;

interface ITransferVerifier {
    function verifyProof(
        uint256[8] calldata proof,
        uint256[32] calldata input
    ) external view;
}
