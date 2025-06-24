/*

After an employee is terminated, the employee will have the right to revoke their data from the system.

this will use a ZK proof to verify the employee knows who they are and that they are terminated.

If the ZK proof is valid, the employee data will be revoked from the system.

*/

pragma circom 2.1.9;

include "./components_2.circom";
include "./components.circom";

/*

TODO:

update this to verify the ciphertext of the bonus ID that the business will store on-chain
The user should be able to generate a proof to show that the received the key so they can claim the bonus.
The way this is being done is that the user will recreate the ciphertext after decrypting it with the key they received.
*/


template EmployeeData() {

    signal input EmployeeId; // unencrypted id of the employee
    signal input EmployeeName; // unencrypted name of the employee
    signal input EmployeeBonusId; // unencrypted bonus id of the employee

    signal input EmployerPublicKey[2]; // used as auth key for the following elements - Status and Name

    signal input SharedKey[2]; // shared key for the following elements - status and name
    
    signal input EmployeePrivateKey; // Private key of the employee used as the shared key for encryption
    signal input EmployeePublicKey[2];

    signal input EmployeeBonusPrivateKey; // Private key of the employee used as the shared key for encryption
    signal input EmployeeBonusPublicKey[2];
    
    // Employee ID is encrypted with the employee's public key not the shared key
    signal input EmployeeIdPCT[4]; // unencrypted termination ID of the employee
    signal input EmployeeIdPCTAuthKey[2];
    signal input EmployeeIdPCTNonce;
    signal input EmployeeIdPCTRandom;

    // Bonus ID is encrypted with the employee's public key
    signal input BonusIdPCT[4];
    signal input BonusIdPCTAuthKey[2];
    signal input BonusIdPCTNonce;
    signal input BonusIdPCTRandom;

    // Employee Status is encrypted with the shared key not the employee's public key
    signal input EmployeeNamePCT[4]; // unencrypted termination ID of the employee
    signal input EmployeeNamePCTNonce;

    // Verify that the shared key is well-formed
    component checkSharedKey = CheckSharedKey();
    checkSharedKey.sharedKey[0] <== SharedKey[0];
    checkSharedKey.sharedKey[1] <== SharedKey[1];
    checkSharedKey.pubKey[0] <== EmployerPublicKey[0];
    checkSharedKey.pubKey[1] <== EmployerPublicKey[1];
    checkSharedKey.privateKey <== EmployeePrivateKey;

    // Verify that the employee's public key is well-formed
    component checkEmployeePK = CheckPublicKey();
    checkEmployeePK.privKey <== EmployeePrivateKey;
    checkEmployeePK.pubKey[0] <== EmployeePublicKey[0];
    checkEmployeePK.pubKey[1] <== EmployeePublicKey[1];

    // Verify that the employee's encrypted id is well-formed; encrypted with the employee's public key
    component checkEmployeeIdPCT = CheckPCT();
    checkEmployeeIdPCT.publicKey[0] <== EmployeePublicKey[0];
    checkEmployeeIdPCT.publicKey[1] <== EmployeePublicKey[1];
    checkEmployeeIdPCT.pct <== EmployeeIdPCT;
    checkEmployeeIdPCT.authKey[0] <== EmployeeIdPCTAuthKey[0];
    checkEmployeeIdPCT.authKey[1] <== EmployeeIdPCTAuthKey[1];
    checkEmployeeIdPCT.nonce <== EmployeeIdPCTNonce;
    checkEmployeeIdPCT.random <== EmployeeIdPCTRandom;
    checkEmployeeIdPCT.value <== EmployeeId;

    // Verify that the employee's encrypted bonus id is well-formed; encrypted with the employee's public key
    component checkBonusIdPCT = CheckPCT();
    checkBonusIdPCT.publicKey[0] <== EmployeeBonusPublicKey[0];
    checkBonusIdPCT.publicKey[1] <== EmployeeBonusPublicKey[1];
    checkBonusIdPCT.pct <== BonusIdPCT;
    checkBonusIdPCT.authKey[0] <== BonusIdPCTAuthKey[0];
    checkBonusIdPCT.authKey[1] <== BonusIdPCTAuthKey[1];
    checkBonusIdPCT.nonce <== BonusIdPCTNonce;
    checkBonusIdPCT.random <== BonusIdPCTRandom;
    checkBonusIdPCT.value <== EmployeeBonusId;

    // Verify that the employee's encrypted status is well-formed; encrypted with the shared key
    component checkEmployeeNamePCT = CheckPCTEcdhSharedKey();
    checkEmployeeNamePCT.publicKey[0] <== SharedKey[0];
    checkEmployeeNamePCT.publicKey[1] <== SharedKey[1];
    checkEmployeeNamePCT.pct <== EmployeeNamePCT;
    checkEmployeeNamePCT.authKey[0] <== EmployerPublicKey[0]; // AuthKey is the employers public key
    checkEmployeeNamePCT.authKey[1] <== EmployerPublicKey[1]; // AuthKey is the employers public key
    checkEmployeeNamePCT.nonce <== EmployeeNamePCTNonce;
    checkEmployeeNamePCT.random <== EmployeePrivateKey; // Random is the employee's private key
    checkEmployeeNamePCT.value <== EmployeeName;
}

component main { public [ EmployerPublicKey, SharedKey, EmployeePublicKey, EmployeeBonusPublicKey, EmployeeIdPCT, EmployeeIdPCTAuthKey, EmployeeIdPCTNonce, BonusIdPCT, BonusIdPCTAuthKey, BonusIdPCTNonce, EmployeeNamePCT, EmployeeNamePCTNonce ] } = EmployeeData();