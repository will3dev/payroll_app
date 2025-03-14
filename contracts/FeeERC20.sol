// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

import {SimpleERC20} from "./SimpleERC20.sol";

/**
 * @title FeeERC20
 * @dev ERC20 token with a fee mechanism for testing TransferFailed error
 */
contract FeeERC20 is SimpleERC20 {
    // Fee percentage (in basis points, 1 = 0.01%)
    uint256 public feeRate;
    // Fee collector address
    address public feeCollector;

    constructor(
        string memory name,
        string memory symbol,
        uint8 decimal,
        uint256 feeRates,
        address feeCollectors
    ) SimpleERC20(name, symbol, decimal) {
        feeRate = feeRates;
        feeCollector = feeCollectors;
    }

    /**
     * @dev Set the fee rate
     * @param feeRates New fee rate in basis points
     */
    function setFeeRate(uint256 feeRates) external {
        feeRate = feeRates;
    }

    /**
     * @dev Set the fee collector
     * @param feeCollectors New fee collector address
     */
    function setFeeCollector(address feeCollectors) external {
        feeCollector = feeCollectors;
    }

    /**
     * @dev Override transferFrom to apply a fee
     * @param sender The address to transfer from
     * @param recipient The address to transfer to
     * @param amount The amount to transfer
     * @return A boolean that indicates if the operation was successful
     */
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) public virtual override returns (bool) {
        address spender = _msgSender();

        // Calculate fee
        uint256 fee = (amount * feeRate) / 10000;
        uint256 amountAfterFee = amount - fee;

        // Deduct allowance
        _spendAllowance(sender, spender, amount);

        // Transfer amount after fee to recipient
        _transfer(sender, recipient, amountAfterFee);

        // Transfer fee to fee collector
        if (fee > 0) {
            _transfer(sender, feeCollector, fee);
        }

        return true;
    }
}
