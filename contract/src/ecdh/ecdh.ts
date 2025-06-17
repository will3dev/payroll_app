import {
    Base8,
    Fr,
    type Point,
    addPoint,
    mulPointEscalar,
} from "@zk-kit/baby-jubjub";
import { formatPrivKeyForBabyJub, genRandomBabyJubValue, genEcdhSharedKey } from "maci-crypto";
import { randomBytes, createHash, createCipheriv, createDecipheriv } from "crypto";

// Baby Jubjub curve parameters
const PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

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

/**
 * Converts a string to a point on the Baby Jubjub curve
 * @param message The string message to convert
 * @returns A point on the curve as [bigint, bigint]
 */
export function stringToPoint(message: string): [bigint, bigint] {
    // Hash the message to get a 32-byte buffer
    const messageBuffer = Buffer.from(message, 'utf8');
    const hash = createHash('sha256').update(messageBuffer).digest();
    
    // Convert the hash to a bigint
    const hashBigInt = BigInt('0x' + hash.toString('hex'));
    
    // Use the hash to derive a point on the curve
    // We'll use the first 32 bytes as x coordinate
    // and derive y from the curve equation
    const x = hashBigInt % PRIME;
    
    // Calculate y^2 = (1 + dx^2)/(1 + ax^2) mod p
    // For Baby Jubjub: a = 168700, d = 168696
    const A = 168700n;
    const D = 168696n;
    
    const x2 = (x * x) % PRIME;
    const numerator = (1n + (D * x2)) % PRIME;
    const denominator = (1n + (A * x2)) % PRIME;
    
    // Find modular multiplicative inverse of denominator
    const denomInv = modInverse(denominator, PRIME);
    if (!denomInv) {
        throw new Error('Failed to find modular inverse');
    }
    
    // Calculate y^2
    const y2 = (numerator * denomInv) % PRIME;
    
    // Find square root of y^2
    const y = modSqrt(y2, PRIME);
    if (!y) {
        throw new Error('Failed to find square root');
    }
    
    return [x, y];
}

/**
 * Finds modular multiplicative inverse using Extended Euclidean Algorithm
 */
function modInverse(a: bigint, m: bigint): bigint | null {
    let [old_r, r] = [a, m];
    let [old_s, s] = [1n, 0n];
    let [old_t, t] = [0n, 1n];
    
    while (r !== 0n) {
        const quotient = old_r / r;
        [old_r, r] = [r, old_r - quotient * r];
        [old_s, s] = [s, old_s - quotient * s];
        [old_t, t] = [t, old_t - quotient * t];
    }
    
    if (old_r !== 1n) return null;
    return ((old_s % m) + m) % m;
}

/**
 * Finds modular square root using Tonelli-Shanks algorithm
 */
function modSqrt(n: bigint, p: bigint): bigint | null {
    if (n === 0n) return 0n;
    if (p === 2n) return n;
    
    // Check if n is a quadratic residue
    if (modPow(n, (p - 1n) / 2n, p) !== 1n) {
        return null;
    }
    
    // Find Q and S such that p - 1 = Q * 2^S
    let Q = p - 1n;
    let S = 0n;
    while (Q % 2n === 0n) {
        Q /= 2n;
        S += 1n;
    }
    
    // Find a quadratic non-residue z
    let z = 2n;
    while (modPow(z, (p - 1n) / 2n, p) !== p - 1n) {
        z += 1n;
    }
    
    let M = S;
    let c = modPow(z, Q, p);
    let t = modPow(n, Q, p);
    let R = modPow(n, (Q + 1n) / 2n, p);
    
    while (t !== 1n) {
        let i = 0n;
        let temp = t;
        while (temp !== 1n && i < M) {
            temp = (temp * temp) % p;
            i += 1n;
        }
        
        if (i === 0n) return R;
        
        const b = modPow(c, 1n << (M - i - 1n), p);
        M = i;
        c = (b * b) % p;
        t = (t * c) % p;
        R = (R * b) % p;
    }
    
    return R;
}

/**
 * Computes (base^exponent) % modulus efficiently
 */
function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
    if (modulus === 1n) return 0n;
    
    let result = 1n;
    base = base % modulus;
    
    while (exponent > 0n) {
        if (exponent % 2n === 1n) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent = exponent / 2n;
    }
    
    return result;
}













