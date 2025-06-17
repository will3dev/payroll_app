/*

After an employee is terminated, the employee will have the right to revoke their data from the system.

this will use a ZK proof to verify the employee knows who they are and that they are terminated.

If the ZK proof is valid, the employee data will be revoked from the system.

*/

pragma circom 2.1.9;

include "./components_2.circom";
include "./components.circom";



template RevokeEmployeeData() {

    signal input EmployeeStatus; // unencrypted status of the employee
    signal input EmployeeId; // unencrypted id of the employee

    signal input EmployerPublicKey[2]; // used as auth key for the following elements - Status and Name

    signal input SharedKey[2]; // shared key for the following elements - status and name
    
    signal input EmployeePrivateKey; // Private key of the employee used as the shared key for encryption
    signal input EmployeePublicKey[2];

    // Employee ID is encrypted with the employee's public key not the shared key
    signal input EmployeeIdPCT[4]; // unencrypted termination ID of the employee
    signal input EmployeeIdPCTAuthKey[2];
    signal input EmployeeIdPCTNonce;
    signal input EmployeeIdPCTRandom;

    // Employee Status is encrypted with the shared key not the employee's public key
    signal input EmployeeStatusPCT[4]; // unencrypted termination ID of the employee
    signal input EmployeeStatusPCTNonce;

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

    // Verify that the employee's status is in a terminal state, allowing them to revoke their data
    EmployeeStatus === 0;
    
    // Verify that the employee's encrypted status is well-formed; encrypted with the shared key
    component checkEmployeeStatusPCT = CheckPCT();
    checkEmployeeStatusPCT.publicKey[0] <== SharedKey[0];
    checkEmployeeStatusPCT.publicKey[1] <== SharedKey[1];
    checkEmployeeStatusPCT.pct <== EmployeeStatusPCT;
    checkEmployeeStatusPCT.authKey[0] <== EmployerPublicKey[0]; // AuthKey is the employers public key
    checkEmployeeStatusPCT.authKey[1] <== EmployerPublicKey[1]; // AuthKey is the employers public key
    checkEmployeeStatusPCT.nonce <== EmployeeStatusPCTNonce;
    checkEmployeeStatusPCT.random <== EmployeePrivateKey; // Random is the employee's private key
    checkEmployeeStatusPCT.value <== EmployeeStatus;

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
}

component main { public [ EmployeeStatus, EmployeeId, EmployerPublicKey, SharedKey, EmployeePrivateKey, EmployeePublicKey, EmployeeIdPCT, EmployeeIdPCTAuthKey, EmployeeIdPCTNonce, EmployeeIdPCTRandom, EmployeeStatusPCT, EmployeeStatusPCTNonce ] } = RevokeEmployeeData();