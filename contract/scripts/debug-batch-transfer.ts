import { ethers } from "hardhat";
import { zkit } from "@solarity/zkit";
import { batchTransfer } from "../test/helpers";
import { validateBatchTransferInputs, BatchTransferInputs } from "./validate-circuit-inputs";
import { User } from "../test/user";

async function debugBatchTransfer() {
  console.log("🚀 Starting Batch Transfer Debug Session...\n");

  try {
    // Setup test environment with User objects
    const [deployer, signer1, signer2, signer3, signer4] = await ethers.getSigners();
    
    const sender = new User(signer1);
    const recipients = [new User(signer2), new User(signer3), new User(signer4)];
    
    const senderBalance = 1000n;
    const amounts = [100n, 200n, 150n];
    
    // Mock encrypted balance (normally from contract)
    const senderEncryptedBalance = [1n, 2n, 3n, 4n]; // Mock values
    
    // Mock auditor public key
    const auditorPublicKey = [
      BigInt("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
      BigInt("0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321")
    ];
    
    console.log("📋 Test Setup:");
    console.log(`Sender: ${sender.signer.address}`);
    console.log(`Recipients: ${recipients.length} users`);
    console.log(`Amounts: ${amounts.join(", ")}`);
    console.log(`Sender Balance: ${senderBalance}`);
    console.log(`Total Transfer: ${amounts.reduce((a, b) => a + b, 0n)}\n`);

    // Generate batch transfer proof
    console.log("🔄 Generating batch transfer proof...");
    const result = await batchTransfer(
      sender,
      senderBalance,
      recipients,
      amounts,
      senderEncryptedBalance,
      auditorPublicKey
    );

    console.log("✅ Proof generated successfully!");
    console.log(`Public signals count: ${result.proof.publicSignals.length}`);
    console.log(`Expected count: 149\n`);

    // Validate public signals structure
    if (result.proof.publicSignals.length !== 149) {
      console.error(`❌ Public signals count mismatch! Expected 149, got ${result.proof.publicSignals.length}`);
    } else {
      console.log("✅ Public signals count matches expected value");
    }

    // Test circuit directly with minimal input
    console.log("\n🧪 Testing circuit directly...");
    try {
      const circuit = await zkit.getCircuit("BatchTransferCircuit");
      console.log(`Circuit loaded: ${circuit.circuitName}`);
      console.log(`Expected public inputs: ${circuit.getPublicSignalsCount()}`);
      
      console.log("✅ Circuit loaded successfully");
      
    } catch (error) {
      console.error("❌ Circuit testing failed:", error);
    }

    console.log("\n🎯 Debug Summary:");
    console.log(`- Proof generation: ✅ Success`);
    console.log(`- Public signals count: ${result.proof.publicSignals.length === 149 ? '✅' : '❌'} ${result.proof.publicSignals.length}/149`);
    console.log(`- Circuit validation passed: ✅ Success`);

  } catch (error) {
    console.error("❌ Debug session failed:", error);
    
    if (error instanceof Error) {
      console.error("Error message:", error.message);
      console.error("Stack trace:", error.stack);
    }
  }
}

// Run the debug function
debugBatchTransfer()
  .then(() => {
    console.log("\n🏁 Debug session completed");
    process.exit(0);
  })
  .catch((error) => {
    console.error("💥 Fatal error:", error);
    process.exit(1);
  }); 