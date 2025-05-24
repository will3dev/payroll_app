pragma circom 2.1.9;

include "./components.circom";

/* TO DO
Need to perform elgamal subtraction for the sender's balance to determine 


*/



template BatchTransferCircuit(n) {
    // Input signals (private)
    signal input ValueToTransfer; //

    signal input SenderPrivateKey;
    signal input SenderPublicKey[2];
    signal input SenderBalance;
    signal input SenderBalanceC1[2];
    signal input SenderBalanceC2[2];

    signal input SenderVTTC1[2];
    signal input SenderVTTC2[2];

    signal input ReceiverPublicKey[n][2];
    signal input ReceiverVTTC1[n][2];
    signal input ReceiverVTTC2[n][2];
    signal input ReceiverVTTRandom[n];

    signal input ReceiverPCT[n][4];
    signal input ReceiverPCTAuthKey[n][2];
    signal input ReceiverPCTNonce[n];
    signal input ReceiverPCTRandom[n];

    signal input AuditorPublicKey[2];
    signal input AuditorPCT[4];
    signal input AuditorPCTAuthKey[2];
    signal input AuditorPCTNonce;
    signal input AuditorPCTRandom;

    signal input ReceiverAmount[n];

    // Verify that the transfer amount is less than or equal to the sender's balance and is less than the base order
    var baseOrder = 2736030358979909402780800718157159386076813972158567259200215660948447373041;   

    component bitCheck1 = Num2Bits(252);
    bitCheck1.in <== ValueToTransfer;

    component bitCheck2 = Num2Bits(252);
    bitCheck2.in <== baseOrder;

    component lt = LessThan(252);
    lt.in[0] <== ValueToTransfer;
    lt.in[1] <== baseOrder;
    lt.out === 1;

    component bitCheck3 = Num2Bits(252);
    bitCheck3.in <== SenderBalance + 1;

    component checkValue = LessThan(252);
    checkValue.in[0] <== ValueToTransfer;
    checkValue.in[1] <== SenderBalance + 1;
    checkValue.out === 1;

    // Verify that the sender's public key is well-formed
    component checkSenderPK = CheckPublicKey();
    checkSenderPK.privKey <== SenderPrivateKey;
    checkSenderPK.pubKey[0] <== SenderPublicKey[0];
    checkSenderPK.pubKey[1] <== SenderPublicKey[1];

    // Verify that the sender's encrypted balance is well-formed
    component checkSenderBalance = CheckValue();
    checkSenderBalance.value <== SenderBalance;
    checkSenderBalance.privKey <== SenderPrivateKey;
    checkSenderBalance.valueC1[0] <== SenderBalanceC1[0];
    checkSenderBalance.valueC1[1] <== SenderBalanceC1[1];
    checkSenderBalance.valueC2[0] <== SenderBalanceC2[0];
    checkSenderBalance.valueC2[1] <== SenderBalanceC2[1];

    // Verify that the sender's encrypted value to transfer is the transfer amount
    component checkSenderVTTC1 = CheckValue();
    checkSenderVTTC1.value <== ValueToTransfer;
    checkSenderVTTC1.privKey <== SenderPrivateKey;
    checkSenderVTTC1.valueC1[0] <== SenderVTTC1[0];
    checkSenderVTTC1.valueC1[1] <== SenderVTTC1[1];
    checkSenderVTTC1.valueC2[0] <== SenderVTTC2[0];
    checkSenderVTTC1.valueC2[1] <== SenderVTTC2[1];

    // RECEIVER CHECKS
    // Verify that the receiver's encrypted value is the transfer amount by encryption
    var totalTransferAmount = 0;
    component checkReceiverValue[n];

    for (var i = 0; i < n; i++) {
        checkReceiverValue[i] = CheckReceiverValue();
        checkReceiverValue[i].receiverValue <== ReceiverAmount[i];
        checkReceiverValue[i].receiverPublicKey[0] <== ReceiverPublicKey[i][0];
        checkReceiverValue[i].receiverPublicKey[1] <== ReceiverPublicKey[i][1];
        checkReceiverValue[i].receiverRandom <== ReceiverVTTRandom[i];
        checkReceiverValue[i].receiverValueC1[0] <== ReceiverVTTC1[i][0];
        checkReceiverValue[i].receiverValueC1[1] <== ReceiverVTTC1[i][1];
        checkReceiverValue[i].receiverValueC2[0] <== ReceiverVTTC2[i][0]; 
        checkReceiverValue[i].receiverValueC2[1] <== ReceiverVTTC2[i][1];

        totalTransferAmount += ReceiverAmount[i]; // sum of each transfer amount. If each trasfer amount is well-formed then this should equal the total decrypted value.
    }

    // Verify that the total of the receiver values equals the transfer amount
    // Assumes that each transfer amount is well-formed
    // Assumes that the ValueToTransfer is well-formed
    totalTransferAmount === ValueToTransfer;
    
    // For each receiver verify encrypted summary includes the transfer amount and is encrypted with the receiver's public key
    component checkReceiverPCT[n];

    for (var i = 0; i < n; i++) {
        checkReceiverPCT[i] = CheckPCT();
        checkReceiverPCT[i].publicKey[0] <== ReceiverPublicKey[i][0];
        checkReceiverPCT[i].publicKey[1] <== ReceiverPublicKey[i][1];

        for (var j = 0; j < 4; j++) {
            checkReceiverPCT[i].pct[j] <== ReceiverPCT[i][j];
        }
        
        checkReceiverPCT[i].authKey[0] <== ReceiverPCTAuthKey[i][0];
        checkReceiverPCT[i].authKey[1] <== ReceiverPCTAuthKey[i][1];
        checkReceiverPCT[i].nonce <== ReceiverPCTNonce[i];
        checkReceiverPCT[i].random <== ReceiverPCTRandom[i];
        checkReceiverPCT[i].value <== ReceiverAmount[i];
    }

    // Verify auditor's encrypted summary includes the transfer amount and is encrypted with the auditor's public key
    component checkAuditorPCT = CheckPCT();
    checkAuditorPCT.publicKey[0] <== AuditorPublicKey[0];
    checkAuditorPCT.publicKey[1] <== AuditorPublicKey[1];
    checkAuditorPCT.pct <== AuditorPCT;
    checkAuditorPCT.authKey[0] <== AuditorPCTAuthKey[0];
    checkAuditorPCT.authKey[1] <== AuditorPCTAuthKey[1];
    checkAuditorPCT.nonce <== AuditorPCTNonce;
    checkAuditorPCT.random <== AuditorPCTRandom;
    checkAuditorPCT.value <== ValueToTransfer;
}

component main { public [ SenderPublicKey, ReceiverPublicKey, AuditorPublicKey, SenderBalanceC1, SenderBalanceC2, SenderVTTC1, SenderVTTC2, ReceiverVTTC1, ReceiverVTTC2, ReceiverPCT, ReceiverPCTAuthKey, ReceiverPCTNonce, AuditorPCT, AuditorPCTAuthKey, AuditorPCTNonce ] } = BatchTransferCircuit(10);
