// (c) 2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.27;

import {Point} from "./types/Types.sol";
import {IRegistrationVerifier} from "./interfaces/verifiers/IRegistrationVerifier.sol";
import {UserAlreadyRegistered, InvalidChainId, InvalidSender, InvalidRegistrationHash} from "./errors/Errors.sol";

// libraries
import {BabyJubJub} from "./libraries/BabyJubJub.sol";

contract Registrar {
    address public constant BURN_USER =
        0x1111111111111111111111111111111111111111;

    // registration verifier
    IRegistrationVerifier public registrationVerifier;

    /**
     * @dev Mapping of user addresses to their public keys
     */
    mapping(address userAddress => Point userPublicKey) public userPublicKeys;

    /**
     * @dev Store all registration hashes
     */
    mapping(uint256 registrationHash => bool isRegistered) public isRegistered;

    /**
     *
     * @param user Address of the user
     * @param publicKey Public key of the user
     */
    event Register(address indexed user, Point publicKey);

    constructor(address registrationVerifier_) {
        registrationVerifier = IRegistrationVerifier(registrationVerifier_);
        // setting burn user to the identity point (0, 1)
        userPublicKeys[BURN_USER] = Point({x: 0, y: 1});
    }

    /**
     * @param proof Proof of the user
     * @param input Input of the proof
     */
    function register(
        uint256[8] calldata proof,
        uint256[5] calldata input
    ) external {
        address account = address(uint160(input[2]));

        if (msg.sender != account) {
            revert InvalidSender();
        }

        if (block.chainid != input[3]) {
            revert InvalidChainId();
        }

        uint256 registrationHash = input[4];

        if (registrationHash >= BabyJubJub.Q) {
            revert InvalidRegistrationHash();
        }

        registrationVerifier.verifyProof(proof, input);

        if (isRegistered[registrationHash] && isUserRegistered(account)) {
            revert UserAlreadyRegistered();
        }

        _register(account, Point({x: input[0], y: input[1]}), registrationHash);
    }

    /**
     * @dev Returns the burn user address.
     * @return The burn user address.
     */
    function burnUser() external pure returns (address) {
        return BURN_USER;
    }

    /**
     *
     * @param user Address of the user
     *
     * @return bool True if the user is registered
     */
    function isUserRegistered(address user) public view returns (bool) {
        return userPublicKeys[user].x != 0 && userPublicKeys[user].y != 0;
    }

    /**
     *
     * @param user Address of the user
     *
     * @return publicKey Public key of the user as [x, y] coordinates
     */
    function getUserPublicKey(
        address user
    ) public view returns (uint256[2] memory publicKey) {
        return [userPublicKeys[user].x, userPublicKeys[user].y];
    }

    /**
     * @param user Address of the user
     * @param publicKey Public key of the user
     * @param registrationHash Registration hash
     * @dev Internal function for setting user public key
     */
    function _register(
        address user,
        Point memory publicKey,
        uint256 registrationHash
    ) internal {
        userPublicKeys[user] = publicKey;
        isRegistered[registrationHash] = true;
        emit Register(user, publicKey);
    }
}
