// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

interface IMintVerifier {
    function verifyProof(
        uint256[8] calldata proof,
        uint256[24] calldata input
    ) external view;
}
