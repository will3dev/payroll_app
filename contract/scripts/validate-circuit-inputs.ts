import { ethers } from "hardhat";

// Circuit constraints and validation
const FIELD_SIZE = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");
const BASE_ORDER = BigInt("2736030358979909402780800718157159386076813972158567259200215660948447373041");

interface BatchTransferInputs {
  ValueToTransfer: bigint;
  SenderPrivateKey: bigint;
  SenderPublicKey: bigint[];
  SenderBalance: bigint;
  SenderBalanceC1: bigint[];
  SenderBalanceC2: bigint[];
  SenderVTTC1: bigint[];
  SenderVTTC2: bigint[];
  ReceiverPublicKey: bigint[][];
  ReceiverVTTC1: bigint[][];
  ReceiverVTTC2: bigint[][];
  ReceiverVTTRandom: bigint[];
  ReceiverPCT: bigint[][];
  ReceiverPCTAuthKey: bigint[][];
  ReceiverPCTNonce: bigint[];
  ReceiverPCTRandom: bigint[];
  AuditorPublicKey: bigint[];
  AuditorPCT: bigint[];
  AuditorPCTAuthKey: bigint[];
  AuditorPCTNonce: bigint;
  AuditorPCTRandom: bigint;
  ReceiverAmount: bigint[];
}

function validateFieldElement(value: bigint, name: string): boolean {
  if (value < 0n || value >= FIELD_SIZE) {
    console.error(`❌ ${name}: ${value} is not a valid field element (must be 0 <= x < ${FIELD_SIZE})`);
    return false;
  }
  return true;
}

function validatePrivateKey(privateKey: bigint): boolean {
  // Private key should be less than 2^253 for Baby Jubjub
  const maxPrivateKey = 2n ** 253n;
  if (privateKey >= maxPrivateKey) {
    console.error(`❌ Private key ${privateKey} is too large (must be < 2^253)`);
    return false;
  }
  return validateFieldElement(privateKey, "SenderPrivateKey");
}

function validateAmount(amount: bigint, name: string): boolean {
  if (amount < 0n) {
    console.error(`❌ ${name}: ${amount} cannot be negative`);
    return false;
  }
  if (amount >= BASE_ORDER) {
    console.error(`❌ ${name}: ${amount} exceeds base order ${BASE_ORDER}`);
    return false;
  }
  return validateFieldElement(amount, name);
}

function validatePublicKey(publicKey: bigint[], name: string): boolean {
  if (publicKey.length !== 2) {
    console.error(`❌ ${name}: Public key must have exactly 2 elements, got ${publicKey.length}`);
    return false;
  }
  
  let valid = true;
  publicKey.forEach((coord, i) => {
    if (!validateFieldElement(coord, `${name}[${i}]`)) {
      valid = false;
    }
  });
  
  return valid;
}

function validateArrayLength<T>(array: T[], expectedLength: number, name: string): boolean {
  if (array.length !== expectedLength) {
    console.error(`❌ ${name}: Expected length ${expectedLength}, got ${array.length}`);
    return false;
  }
  return true;
}

export function validateBatchTransferInputs(inputs: BatchTransferInputs, numReceivers: number = 10): boolean {
  console.log("🔍 Validating Batch Transfer Circuit Inputs...\n");
  
  let isValid = true;
  
  // 1. Validate basic amounts
  console.log("📊 Validating amounts...");
  if (!validateAmount(inputs.ValueToTransfer, "ValueToTransfer")) isValid = false;
  if (!validateAmount(inputs.SenderBalance, "SenderBalance")) isValid = false;
  
  // Check that ValueToTransfer <= SenderBalance
  if (inputs.ValueToTransfer > inputs.SenderBalance) {
    console.error(`❌ ValueToTransfer (${inputs.ValueToTransfer}) > SenderBalance (${inputs.SenderBalance})`);
    isValid = false;
  }
  
  // 2. Validate private key
  console.log("🔑 Validating private key...");
  if (!validatePrivateKey(inputs.SenderPrivateKey)) isValid = false;
  
  // 3. Validate public keys
  console.log("🔐 Validating public keys...");
  if (!validatePublicKey(inputs.SenderPublicKey, "SenderPublicKey")) isValid = false;
  if (!validatePublicKey(inputs.AuditorPublicKey, "AuditorPublicKey")) isValid = false;
  
  // 4. Validate array lengths
  console.log("📏 Validating array lengths...");
  if (!validateArrayLength(inputs.SenderBalanceC1, 2, "SenderBalanceC1")) isValid = false;
  if (!validateArrayLength(inputs.SenderBalanceC2, 2, "SenderBalanceC2")) isValid = false;
  if (!validateArrayLength(inputs.SenderVTTC1, 2, "SenderVTTC1")) isValid = false;
  if (!validateArrayLength(inputs.SenderVTTC2, 2, "SenderVTTC2")) isValid = false;
  if (!validateArrayLength(inputs.AuditorPCT, 4, "AuditorPCT")) isValid = false;
  if (!validateArrayLength(inputs.AuditorPCTAuthKey, 2, "AuditorPCTAuthKey")) isValid = false;
  
  // 5. Validate receiver arrays
  console.log("👥 Validating receiver arrays...");
  if (!validateArrayLength(inputs.ReceiverPublicKey, numReceivers, "ReceiverPublicKey")) isValid = false;
  if (!validateArrayLength(inputs.ReceiverVTTC1, numReceivers, "ReceiverVTTC1")) isValid = false;
  if (!validateArrayLength(inputs.ReceiverVTTC2, numReceivers, "ReceiverVTTC2")) isValid = false;
  if (!validateArrayLength(inputs.ReceiverVTTRandom, numReceivers, "ReceiverVTTRandom")) isValid = false;
  if (!validateArrayLength(inputs.ReceiverPCT, numReceivers, "ReceiverPCT")) isValid = false;
  if (!validateArrayLength(inputs.ReceiverPCTAuthKey, numReceivers, "ReceiverPCTAuthKey")) isValid = false;
  if (!validateArrayLength(inputs.ReceiverPCTNonce, numReceivers, "ReceiverPCTNonce")) isValid = false;
  if (!validateArrayLength(inputs.ReceiverPCTRandom, numReceivers, "ReceiverPCTRandom")) isValid = false;
  if (!validateArrayLength(inputs.ReceiverAmount, numReceivers, "ReceiverAmount")) isValid = false;
  
  // 6. Validate receiver data structure
  console.log("🔍 Validating receiver data structure...");
  for (let i = 0; i < Math.min(inputs.ReceiverPublicKey.length, numReceivers); i++) {
    if (!validatePublicKey(inputs.ReceiverPublicKey[i], `ReceiverPublicKey[${i}]`)) isValid = false;
    if (!validateArrayLength(inputs.ReceiverVTTC1[i], 2, `ReceiverVTTC1[${i}]`)) isValid = false;
    if (!validateArrayLength(inputs.ReceiverVTTC2[i], 2, `ReceiverVTTC2[${i}]`)) isValid = false;
    if (!validateArrayLength(inputs.ReceiverPCT[i], 4, `ReceiverPCT[${i}]`)) isValid = false;
    if (!validateArrayLength(inputs.ReceiverPCTAuthKey[i], 2, `ReceiverPCTAuthKey[${i}]`)) isValid = false;
    if (!validateAmount(inputs.ReceiverAmount[i], `ReceiverAmount[${i}]`)) isValid = false;
  }
  
  // 7. Validate amount consistency
  console.log("⚖️ Validating amount consistency...");
  const totalReceiverAmount = inputs.ReceiverAmount.reduce((sum, amount) => sum + amount, 0n);
  if (totalReceiverAmount !== inputs.ValueToTransfer) {
    console.error(`❌ Sum of ReceiverAmount (${totalReceiverAmount}) != ValueToTransfer (${inputs.ValueToTransfer})`);
    isValid = false;
  }
  
  // 8. Validate all field elements
  console.log("🔢 Validating field elements...");
  const allValues: Array<{ value: bigint; name: string }> = [
    ...inputs.SenderBalanceC1.map((v, i) => ({ value: v, name: `SenderBalanceC1[${i}]` })),
    ...inputs.SenderBalanceC2.map((v, i) => ({ value: v, name: `SenderBalanceC2[${i}]` })),
    ...inputs.SenderVTTC1.map((v, i) => ({ value: v, name: `SenderVTTC1[${i}]` })),
    ...inputs.SenderVTTC2.map((v, i) => ({ value: v, name: `SenderVTTC2[${i}]` })),
    ...inputs.AuditorPCT.map((v, i) => ({ value: v, name: `AuditorPCT[${i}]` })),
    ...inputs.AuditorPCTAuthKey.map((v, i) => ({ value: v, name: `AuditorPCTAuthKey[${i}]` })),
    { value: inputs.AuditorPCTNonce, name: "AuditorPCTNonce" },
    { value: inputs.AuditorPCTRandom, name: "AuditorPCTRandom" },
  ];
  
  // Add receiver field elements
  for (let i = 0; i < Math.min(inputs.ReceiverPublicKey.length, numReceivers); i++) {
    allValues.push(
      ...inputs.ReceiverVTTC1[i].map((v, j) => ({ value: v, name: `ReceiverVTTC1[${i}][${j}]` })),
      ...inputs.ReceiverVTTC2[i].map((v, j) => ({ value: v, name: `ReceiverVTTC2[${i}][${j}]` })),
      ...inputs.ReceiverPCT[i].map((v, j) => ({ value: v, name: `ReceiverPCT[${i}][${j}]` })),
      ...inputs.ReceiverPCTAuthKey[i].map((v, j) => ({ value: v, name: `ReceiverPCTAuthKey[${i}][${j}]` })),
      { value: inputs.ReceiverVTTRandom[i], name: `ReceiverVTTRandom[${i}]` },
      { value: inputs.ReceiverPCTNonce[i], name: `ReceiverPCTNonce[${i}]` },
      { value: inputs.ReceiverPCTRandom[i], name: `ReceiverPCTRandom[${i}]` }
    );
  }
  
  for (const { value, name } of allValues) {
    if (!validateFieldElement(value, name)) isValid = false;
  }
  
  console.log(`\n${isValid ? '✅' : '❌'} Validation ${isValid ? 'PASSED' : 'FAILED'}`);
  return isValid;
}

// Export for use in other scripts
export { FIELD_SIZE, BASE_ORDER, BatchTransferInputs }; 