// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.27;
import {EncryptedBalance, EGCT, BalanceHistory, AmountPCT} from "./types/Types.sol";
import {BabyJubJub} from "./libraries/BabyJubJub.sol";

contract EncryptedUserBalances {
    mapping(address user => mapping(uint256 tokenId => EncryptedBalance balance))
        public balances;

    /**
     *
     * @param user User address
     * @return eGCT Elgamal Ciphertext
     * @return nonce Nonce
     * @dev Returns the balance of the user for the standalone token (tokenId = 0)
     */
    function balanceOfStandalone(
        address user
    )
        external
        view
        returns (
            EGCT memory eGCT,
            uint256 nonce,
            AmountPCT[] memory amountPCTs,
            uint256[7] memory balancePCT,
            uint256 transactionIndex
        )
    {
        return balanceOf(user, 0);
    }

    /**
     * @param user User address
     * @param tokenId Token ID
     * @return eGCT Elgamal Ciphertext
     * @return nonce Nonce
     * @dev Returns the balance of the user for the given token
     */
    function balanceOf(
        address user,
        uint256 tokenId
    )
        public
        view
        returns (
            EGCT memory eGCT,
            uint256 nonce,
            AmountPCT[] memory amountPCTs,
            uint256[7] memory balancePCT,
            uint256 transactionIndex
        )
    {
        EncryptedBalance storage balance = balances[user][tokenId];
        return (
            balance.eGCT,
            balance.nonce,
            balance.amountPCTs,
            balance.balancePCT,
            balance.transactionIndex
        );
    }

    ///////////////////////////////////////////////////
    ///               Internal Functions            ///
    ///////////////////////////////////////////////////

    /**
     * @param user User address
     * @param tokenId Token ID
     * @dev Adds the amount to the user's balance
     */
    function _addToUserBalance(
        address user,
        uint256 tokenId,
        EGCT memory eGCT,
        uint256[7] memory amountPCT
    ) internal {
        EncryptedBalance storage balance = balances[user][tokenId];

        // if user balance is not initialized, initialize it
        if (balance.eGCT.c1.x == 0 && balance.eGCT.c1.y == 0) {
            balance.eGCT = eGCT;
        } else {
            // if user balance is already initialized, add the encrypted amount to the balance
            balance.eGCT.c1 = BabyJubJub._add(balance.eGCT.c1, eGCT.c1);
            balance.eGCT.c2 = BabyJubJub._add(balance.eGCT.c2, eGCT.c2);
        }

        // in all the case
        _addToUserHistory(user, tokenId, amountPCT);
    }

    /**
     * @param user User address
     * @param tokenId Token ID
     * @dev Subtracts the amount from the user's balance
     */
    function _subtractFromUserBalance(
        address user,
        uint256 tokenId,
        EGCT memory eGCT,
        uint256[7] memory balancePCT,
        uint256 transactionIndex
    ) internal {
        EncryptedBalance storage balance = balances[user][tokenId];

        // since we are encrypting the negated amount, we need to add it to the balance
        balance.eGCT.c1 = BabyJubJub._sub(balance.eGCT.c1, eGCT.c1);
        balance.eGCT.c2 = BabyJubJub._sub(balance.eGCT.c2, eGCT.c2);

        // delete the amount pct from the balance
        _deleteUserHistory(user, tokenId, transactionIndex);

        // update balance pct
        balance.balancePCT = balancePCT;
    }

    /**
     * @param user User address
     * @param tokenId Token ID
     * @dev Adds the balance hash to the user's history
     * @dev Hash EGCT with the nonce and mark the result as valid
     *      every time user send a transaction nonce is increased by 1
     *      so the balance hash is unique for each transaction and sender must prove
     *      that the balance hash is known beforehand with the current nonce
     */
    function _addToUserHistory(
        address user,
        uint256 tokenId,
        uint256[7] memory amountPCT
    ) internal {
        EncryptedBalance storage balance = balances[user][tokenId];

        uint256 nonce = balance.nonce;
        uint256 balanceHash = _hashEGCT(balance.eGCT);
        balanceHash = uint256(keccak256(abi.encode(balanceHash, nonce)));

        // mark the balance hash as valid
        balance.balanceList[balanceHash] = BalanceHistory({
            index: balance.transactionIndex,
            isValid: true
        });

        // add the amount pct to the balance
        balance.amountPCTs.push(
            AmountPCT({pct: amountPCT, index: balance.transactionIndex})
        );

        balance.transactionIndex++;
    }

    /**
     * @param user User address
     * @param tokenId Token ID
     * @dev Commits the user's balance
     * @dev Hash EGCT with the nonce and mark the result as valid
     *      every time user send a transaction nonce is increased by 1
     *      so the balance hash is unique for each transaction and sender must prove
     *      that the balance hash is known beforehand with the current nonce
     */
    function _commitUserBalance(address user, uint256 tokenId) internal {
        EncryptedBalance storage balance = balances[user][tokenId];

        uint256 nonce = balance.nonce;
        uint256 balanceHash = _hashEGCT(balance.eGCT);
        balanceHash = uint256(keccak256(abi.encode(balanceHash, nonce)));

        balance.balanceList[balanceHash] = BalanceHistory({
            index: balance.transactionIndex,
            isValid: true
        });

        balance.transactionIndex++;
    }

    /**
     * @param user User address
     * @param tokenId Token ID
     * @dev Deletes the user's history
     * @dev Instead of deleting the history mapping one by one, we can just
     *      increase the nonce by one and the old history will be mark as invalid
     */
    function _deleteUserHistory(
        address user,
        uint256 tokenId,
        uint256 transactionIndex
    ) internal {
        EncryptedBalance storage balance = balances[user][tokenId];

        for (uint256 i = balance.amountPCTs.length; i > 0; i--) {
            uint256 index = i - 1;

            if (balance.amountPCTs[index].index <= transactionIndex) {
                balance.amountPCTs[index] = balance.amountPCTs[
                    balance.amountPCTs.length - 1
                ];
                balance.amountPCTs.pop();
            }
        }

        balance.nonce++;

        _commitUserBalance(user, tokenId);
    }

    /**
     * @param user User address
     * @param tokenId Token ID
     * @param balanceHash Balance hash
     * @return isValid True if the balance hash is valid
     * @dev Hash the provided eGCT with the current nonce and check if it's in the history
     */
    function _isBalanceValid(
        address user,
        uint256 tokenId,
        uint256 balanceHash
    ) internal view returns (bool, uint256) {
        uint256 nonce = balances[user][tokenId].nonce;
        uint256 hashWithNonce = uint256(
            keccak256(abi.encode(balanceHash, nonce))
        );
        return (
            balances[user][tokenId].balanceList[hashWithNonce].isValid,
            balances[user][tokenId].balanceList[hashWithNonce].index
        );
    }

    /**
     * @param eGCT Elgamal Ciphertext
     * @return hash of the Elgamal Ciphertext CRH(eGCT)
     */
    function _hashEGCT(EGCT memory eGCT) internal pure returns (uint256) {
        return
            uint256(
                keccak256(
                    abi.encode(eGCT.c1.x, eGCT.c1.y, eGCT.c2.x, eGCT.c2.y)
                )
            );
    }
}
