// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

interface IRegistrationVerifier {
    function verifyProof(
        uint256[8] calldata proof,
        uint256[5] calldata input
    ) external view;
}
