import {
    Base8,
    Fr,
    type Point,
    addPoint,
    mulPointEscalar,
} from "@zk-kit/baby-jubjub";
import { formatPrivKeyForBabyJub, genRandomBabyJubValue, genEcdhSharedKey } from "maci-crypto";
import { randomBytes, createHash, createCipheriv, createDecipheriv } from "crypto";

export interface EncryptedMessage {
    encryptedMessage: Uint8Array; // combined IV (12 bytes) + Tag (16 bytes) + Ciphertext() 
}

export const encryptMessageEcdh = (
    publicKey: [bigint, bigint],
    privateKey: bigint,
    message: string
): EncryptedMessage => {
    // Hash the shared key to get AES key
    const aesKey = generateSharedKeyForEcdh(privateKey, publicKey);
    // Generate random IV (12 bytes for GCM)
    const iv = randomBytes(12);
    
    // Create cipher
    const cipher = createCipheriv("aes-256-gcm", aesKey, iv);
    
    // Encrypt the message
    const encrypted = Buffer.concat([
        cipher.update(message, "utf8"),
        cipher.final()
    ]);
    
    // Get authentication tag
    const tag = cipher.getAuthTag();

    const combined = Buffer.concat([iv, tag, encrypted])

    return { encryptedMessage: new Uint8Array(combined) };
};

export const decryptMessageEcdh = (
    publicKey: [bigint, bigint], // public key of the sender
    privateKey: bigint,  // private key of the receiver
    encryptedMessage: EncryptedMessage
): string => {
    const message = encryptedMessage.encryptedMessage;

    const iv = message.slice(0, 12); // iv is 12 bytes for GCM
    const tag = message.slice(12,28); // tag is 16 bytes for GCM
    const ciphertext = message.slice(28); // extract the ciphertext

    // Generate the shared key for the ECDH
    const sharedKey = generateSharedKeyForEcdh(privateKey, publicKey);

    // Decrypt the message
    const decipher = createDecipheriv("aes-256-gcm", sharedKey, iv);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
    ]);

    return decrypted.toString();
}



// Helper function to generate a new key pair for ECDH
export const generateSharedKeyForEcdh = (
    privateKey: bigint,
    publicKey: [bigint, bigint]
): Buffer => {
    // Generate shared key using ECDH
    const sharedKey = genEcdhSharedKey(privateKey, publicKey);
    
    // Convert shared key bigint array to Buffer for hashing
    const sharedKeyBuffer = Buffer.concat([
        Buffer.from(sharedKey[0].toString(16).padStart(64, '0'), 'hex'),
        Buffer.from(sharedKey[1].toString(16).padStart(64, '0'), 'hex')
    ]);
    
    // Hash the shared key to get AES key
    const aesKey = createHash("sha256").update(sharedKeyBuffer).digest();

    return aesKey;
}













