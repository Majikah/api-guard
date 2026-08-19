import { promises as fs } from "fs";
import * as path from "path";

// Adjust this import path depending on where you place this script
// and whether you are importing locally or from the installed package.
import { APIGuard } from "../src/api-guard";

async function generateAndStoreKeys() {
  try {
    console.log("Generating APIGuard Ed25519 keypair...");

    // 1. Generate the keypair
    const keys = APIGuard.generateKeyPair(); //[cite: 13]

    // 2. Define the output directory and file path
    const outDir = path.resolve(process.cwd(), "_gen");
    const outFile = path.join(outDir, "keypair.json");

    // 3. Ensure the target directory exists
    await fs.mkdir(outDir, { recursive: true });

    // 4. Write the payload to JSON format
    await fs.writeFile(outFile, JSON.stringify(keys, null, 2), "utf-8");

    console.log(
      `✅ Keypair successfully generated and saved to:\n   ${outFile}`,
    );
    console.log(
      `\n⚠️  IMPORTANT: Do not commit your private key to version control!`,
    );
    console.log(
      `   Make sure '_gen/' or '_gen/keypair.json' is in your .gitignore.`,
    );
  } catch (error) {
    console.error("❌ Failed to generate or save keypair:", error);
    process.exit(1);
  }
}

generateAndStoreKeys();
