// (c) 2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.27;

interface IMintVerifier {
    function verifyProof(
        uint256[8] calldata proof,
        uint256[24] calldata input
    ) external view;
}
