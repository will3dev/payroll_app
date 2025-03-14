// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.27;

import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";

contract TokenTracker is Ownable2Step {
    // starting from 1 becase 0 is for standalone version of the EncryptedERC
    uint256 public nextTokenId = 1;
    // indicates if the contract is a converter
    bool public isConverter;

    // token address to token id
    mapping(address tokenAddress => uint256 tokenId) public tokenIds;

    // token id to token address
    mapping(uint256 tokenId => address tokenAddress) public tokenAddresses;

    // array of token addresses
    address[] public tokens;

    // token address to boolean
    mapping(address tokenAddress => bool isBlacklisted)
        public blacklistedTokens;

    error TokenBlacklisted(address token);

    constructor(bool isConverter_) Ownable(msg.sender) {
        isConverter = isConverter_;
    }

    /**
     * @param token Address of the token to blacklist
     * @param blacklisted Boolean indicating if token should be blacklisted
     * @dev Only owner can call this function
     */
    function setTokenBlacklist(
        address token,
        bool blacklisted
    ) external onlyOwner {
        blacklistedTokens[token] = blacklisted;
    }

    /**
     * @return Array of token addresses
     */
    function getTokens() external view returns (address[] memory) {
        return tokens;
    }

    /**
     * @param tokenAddress Address of the token to check
     * @return bool True if token is blacklisted
     */
    function isTokenBlacklisted(
        address tokenAddress
    ) public view returns (bool) {
        return blacklistedTokens[tokenAddress];
    }

    /**
     * @param tokenAddress Address of the token
     * @dev Adds a token to the tracker
     */
    function _addToken(address tokenAddress) internal {
        uint256 newTokenId = nextTokenId;
        tokenIds[tokenAddress] = newTokenId;
        tokenAddresses[newTokenId] = tokenAddress;
        tokens.push(tokenAddress);
        nextTokenId++;
    }
}
