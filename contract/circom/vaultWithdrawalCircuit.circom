pragma circom 2.1.9;

include "./components.circom";
include "./circomlib/comparators.circom";

/* 

Need to prove the following elements:

1. Sender's public key is well formed
2. Shared public key is well formed
3. User knows the available balance
4. User knows the distribution amount
5. The requested distribution is less than the available balance of the vault
6. 
6. The requested distribution is calculated correctly

How is the distribution calculated:

SB = start block of vault
CB = current block
E = blocks per epoch
ADA = Allowed distribution


First calculate the total epochs since vault start
Then calculate the number of epochs since last withdrawal
Calculate difference between the two
Diff * AllowedDistribution is the amount to distribute


Amount to Distribute = 

Need to update the vault contracts. update how vault settings to use withdrawals with PCT value and elGamal value

The elGamal value will be extracted from the proof and compared against in the contract

*/



template CheckDistributionAmount() {

    // private inputs
    // vault settings 
    signal input epochLength;
    signal input startBlock;
    signal input currentBlock;
    signal input distributionAmount; // this is the amount a user can draw each epoch

    signal input newTotalWithdraws;

    // integer division calculation
    signal input epochsSinceStart;
    signal input remainder;
    
    signal lifetimeEarning;

    // check that current block is less than the last withdraw block
    component lt1 = LessThan(252);
    lt1.in[0] <== startBlock;
    lt1.in[1] <== currentBlock+1;
    lt1.out === 1;

    signal diff;
    diff <== (currentBlock - startBlock);

    component lt2 = LessThan(252);
    lt2.in[0] <== remainder;
    lt2.in[1] <== epochLength;
    lt2.out === 1;

    signal calculatedDiff;
    calculatedDiff <== (epochsSinceStart * epochLength) + remainder;
    calculatedDiff === diff;
    
    lifetimeEarning <== epochsSinceStart * distributionAmount;

    // check that requested requested withdrawal amount + total withdrawals, doesn't exceed lifetime earnings
    component lt3 = LessThan(252);
    lt3.in[0] <== newTotalWithdraws;
    lt3.in[1] <== lifetimeEarning;
    lt3.out === 1;

}



template VaultWithdrawalCircuit () {
    
    signal input withdrawalAmount;

    // public inputs
    signal input senderPrivateKey;
    signal input senderPublicKey[2]; // public 
    signal input vaultBalance;
    signal input vaultBalanceC1[2];  // public
    signal input vaultBalanceC2[2];  // public 

    signal input funderPublicKey[2]; // public 

    signal input withdrawalAmountC1[2]; // public 
    signal input withdrawalAmountC2[2]; // public
 
    signal input withdrawalAmountPCT[4]; // public
    signal input withdrawalAmountAuthKey[2]; // public
    signal input withdrawalAmountNonce; // public 
    signal input withdrawalAmountRandom;

    // Withdrawal history information
    signal input totalWithdraw; // decrypted value

    signal input totalWithdrawC1[2];  // public 
    signal input totalWithdrawC2[2];  // public 

    signal input newTotalWithdraws; // decrypted value
    signal input newTotalWithdrawsPCT[4]; // ciphertext public 
    signal input newTotalWithdrawsAuthKey[2]; // public 
    signal input newTotalWithdrawsNonce; // public 
    signal input newTotalWithdrawsRandom;

    signal input AuditorPublicKey[2]; // public 
    signal input AuditorPCT[4]; // public
    signal input AuditorPCTAuthKey[2]; // public 
    signal input AuditorPCTNonce; // public 
    signal input AuditorPCTRandom;

    signal input sharedKey[2]; // public 

    // vault settings 
    signal input epochLength; // public 
    signal input startBlock; // public
    signal input currentBlock; // public 
    signal input epochsSinceStart;
    signal input remainder;
    
    signal input distributionAmount; // this is the amount a user can draw each epoch
    signal input distributionAmountPCT[4]; // public 
    signal input distributionAmountNonce; // public 

    // Verify that the transfer amount is less than or equal to the sender's balance and is less than the base order
    var baseOrder = 2736030358979909402780800718157159386076813972158567259200215660948447373041;   
    
    component bitCheck1 = Num2Bits(252);
    bitCheck1.in <== withdrawalAmount;

    component bitCheck2 = Num2Bits(252);
    bitCheck2.in <== baseOrder;

    component lt = LessThan(252);
    lt.in[0] <== withdrawalAmount;
    lt.in[1] <== baseOrder;
    lt.out === 1;

    component bitCheck3 = Num2Bits(252);
    bitCheck3.in <== vaultBalance + 1;

    component checkValue = LessThan(252);
    checkValue.in[0] <== withdrawalAmount;
    checkValue.in[1] <== vaultBalance + 1;
    checkValue.out === 1;

    // verify that the sender's public key is well-formed
    component checkSenderPK = CheckPublicKey();
    checkSenderPK.privKey <== senderPrivateKey;
    checkSenderPK.pubKey[0] <== senderPublicKey[0];
    checkSenderPK.pubKey[1] <== senderPublicKey[1]; 

    // check that the shared key is well-formed
    component checkSharedKey = CheckSharedKey();
    checkSharedKey.sharedKey[0] <== sharedKey[0];
    checkSharedKey.sharedKey[1] <== sharedKey[1];
    checkSharedKey.pubKey[0] <== funderPublicKey[0];
    checkSharedKey.pubKey[1] <== funderPublicKey[1];
    checkSharedKey.privateKey <== senderPrivateKey;
    
    component checkDistributionAmountPCT = CheckPCTEcdhSharedKey();
    checkDistributionAmountPCT.publicKey[0] <== sharedKey[0];
    checkDistributionAmountPCT.publicKey[1] <== sharedKey[1];
    checkDistributionAmountPCT.pct <== distributionAmountPCT;
    checkDistributionAmountPCT.authKey[0] <== funderPublicKey[0];
    checkDistributionAmountPCT.authKey[1] <== funderPublicKey[1];
    checkDistributionAmountPCT.nonce <== distributionAmountNonce;
    checkDistributionAmountPCT.random <== senderPrivateKey;
    checkDistributionAmountPCT.value <== distributionAmount;
    
    // check that user is allowed to withdraw requested amount from vault
    component checkWithdrawIsValid = CheckDistributionAmount();
    checkWithdrawIsValid.epochLength <== epochLength;
    checkWithdrawIsValid.startBlock <== startBlock;
    checkWithdrawIsValid.currentBlock <== currentBlock;
    checkWithdrawIsValid.distributionAmount <== distributionAmount;
    checkWithdrawIsValid.newTotalWithdraws <== newTotalWithdraws;
    checkWithdrawIsValid.remainder <== remainder;
    checkWithdrawIsValid.epochsSinceStart <== epochsSinceStart;
    
    // check that new total withdrawal amount is calculated correctly
    newTotalWithdraws === (totalWithdraw + withdrawalAmount);

    // check that balance is formed correctly
    component checkBalance = CheckValue();
    checkBalance.value <== vaultBalance;
    checkBalance.privKey <== senderPrivateKey;
    checkBalance.valueC1[0] <== vaultBalanceC1[0];
    checkBalance.valueC1[1] <== vaultBalanceC1[1];
    checkBalance.valueC2[0] <== vaultBalanceC2[0];
    checkBalance.valueC2[1] <== vaultBalanceC2[1];
    
    // check that the withdrawal amount encrypted values are correct
    component checkWithdrawalAmount = CheckValue();
    checkWithdrawalAmount.value <== withdrawalAmount;
    checkWithdrawalAmount.privKey <== senderPrivateKey;
    checkWithdrawalAmount.valueC1[0] <== withdrawalAmountC1[0];
    checkWithdrawalAmount.valueC1[1] <== withdrawalAmountC1[1];
    checkWithdrawalAmount.valueC2[0] <== withdrawalAmountC2[0];
    checkWithdrawalAmount.valueC2[1] <== withdrawalAmountC2[1];

    // check that the user has the correct historical value
    component checkTotalWithdrawal = CheckValue();
    checkTotalWithdrawal.value <== totalWithdraw;
    checkTotalWithdrawal.privKey <== senderPrivateKey;
    checkTotalWithdrawal.valueC1[0] <== totalWithdrawC1[0];
    checkTotalWithdrawal.valueC1[1] <== totalWithdrawC1[1];
    checkTotalWithdrawal.valueC2[0] <== totalWithdrawC2[0];
    checkTotalWithdrawal.valueC2[1] <== totalWithdrawC2[1];
    
    // check that PCT value is well formed
    component checkNewTotalWithdrawalPCT = CheckPCT();
    checkNewTotalWithdrawalPCT.publicKey[0] <== senderPublicKey[0];
    checkNewTotalWithdrawalPCT.publicKey[1] <== senderPublicKey[1];
    checkNewTotalWithdrawalPCT.pct <== newTotalWithdrawsPCT;
    checkNewTotalWithdrawalPCT.authKey[0] <== newTotalWithdrawsAuthKey[0];
    checkNewTotalWithdrawalPCT.authKey[1] <== newTotalWithdrawsAuthKey[1];
    checkNewTotalWithdrawalPCT.nonce <== newTotalWithdrawsNonce;
    checkNewTotalWithdrawalPCT.random <== newTotalWithdrawsRandom;
    checkNewTotalWithdrawalPCT.value <== newTotalWithdraws;

    // check the encrypted value generated for the auditor
    component checkAuditorPCT = CheckPCT();
    checkAuditorPCT.publicKey[0] <== AuditorPublicKey[0];
    checkAuditorPCT.publicKey[1] <== AuditorPublicKey[1];
    checkAuditorPCT.pct <== AuditorPCT;
    checkAuditorPCT.authKey[0] <== AuditorPCTAuthKey[0];
    checkAuditorPCT.authKey[1] <== AuditorPCTAuthKey[1];
    checkAuditorPCT.nonce <== AuditorPCTNonce;
    checkAuditorPCT.random <== AuditorPCTRandom;
    checkAuditorPCT.value <== withdrawalAmount;
}


component main { public [
    senderPublicKey, // 0-1
    vaultBalanceC1, // 2-3
    vaultBalanceC2, // 4-5
    funderPublicKey, // 6-7
    withdrawalAmountC1, // 8-9
    withdrawalAmountC2, // 10-11
    withdrawalAmountPCT, // 12-15
    withdrawalAmountAuthKey, // 16-17
    withdrawalAmountNonce, // 18
    totalWithdrawC1, // 19-20
    totalWithdrawC2, // 21-22
    newTotalWithdrawsPCT, // 23-26
    newTotalWithdrawsAuthKey, // 27-28
    newTotalWithdrawsNonce, // 29
    AuditorPublicKey, // 30-31
    AuditorPCT, // 32-35
    AuditorPCTAuthKey, // 36-37
    AuditorPCTNonce, // 38
    sharedKey, // 39-40
    epochLength, // 41
    startBlock, // 42
    currentBlock, // 43
    remainder // 49
    distributionAmountPCT, // 44-47
    distributionAmountNonce, // 48
] } = VaultWithdrawalCircuit();