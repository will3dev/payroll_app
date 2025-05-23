pragma solidity 0.8.27;

interface IBatchTransferVerifier2 {
    function verifyProof(
        uint256[2] memory pointA_,
        uint256[2][2] memory pointB_,
        uint256[2] memory pointC_,
        uint256[149] memory publicSignals_
    ) external view returns (bool verified_);
}