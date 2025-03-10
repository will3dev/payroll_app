// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.27;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract TokenTracker is Ownable {
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

    constructor(bool _isConverter) Ownable(msg.sender) {
        isConverter = _isConverter;
    }

    error TokenBlacklisted(address token);

    /**
     * @return Array of token addresses
     */
    function getTokens() external view returns (address[] memory) {
        return tokens;
    }

    /**
     * @param _token Address of the token to blacklist
     * @param _blacklisted Boolean indicating if token should be blacklisted
     * @dev Only owner can call this function
     */
    function setTokenBlacklist(
        address _token,
        bool _blacklisted
    ) external onlyOwner {
        blacklistedTokens[_token] = _blacklisted;
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
        // Check if token is blacklisted
        if (blacklistedTokens[tokenAddress]) {
            revert TokenBlacklisted(tokenAddress);
        }

        uint256 newTokenId = nextTokenId;
        tokenIds[tokenAddress] = newTokenId;
        tokenAddresses[newTokenId] = tokenAddress;
        tokens.push(tokenAddress);
        nextTokenId++;
    }
}
