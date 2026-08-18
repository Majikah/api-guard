// src/crypto.ts

import * as ed25519 from "@stablelib/ed25519";
import {
  ED25519Keypair,
  ED25519RawPublicKey,
  ED25519RawSecretKey,
  ED25519RawSignature,
} from "./types";

const secureGetRandomValues = crypto.getRandomValues.bind(crypto);
const secureFill = Uint8Array.prototype.fill;

export const IV_LENGTH = 12;

// Re-exported so callers elsewhere (api-guard.ts) can validate decoded
// key/signature lengths without reaching into @stablelib/ed25519 directly.
export const SEED_LENGTH = ed25519.SEED_LENGTH;
export const PUBLIC_KEY_LENGTH = ed25519.PUBLIC_KEY_LENGTH;
export const SECRET_KEY_LENGTH = ed25519.SECRET_KEY_LENGTH;
export const SIGNATURE_LENGTH = ed25519.SIGNATURE_LENGTH;

export function generateRandomBytes(len: number): Uint8Array {
  const b = new Uint8Array(len);
  secureGetRandomValues(b);
  return b;
}

/**
 * Zeroes a byte buffer in place. Best-effort — JS strings can't be wiped,
 * so decoded base64 keys should be converted to bytes as early as possible
 * and the string reference dropped as soon as practical.
 */
export function secureWipe(buf?: Uint8Array): void {
  if (buf) secureFill.call(buf, 0);
}

export function generateEd25519Keypair(): ED25519Keypair {
  const ed = ed25519.generateKeyPair();

  return {
    public: ed.publicKey,
    secret: ed.secretKey,
  };
}

export function getPublicKeyFromSecretKey(
  secret: ED25519RawSecretKey,
): ED25519RawPublicKey {
  const publicKey = ed25519.extractPublicKeyFromSecretKey(secret);

  return publicKey;
}

export function sign(
  secret: ED25519RawSecretKey,
  message: Uint8Array,
): Uint8Array {
  const edSigBytes = ed25519.sign(secret, message);
  return edSigBytes;
}

export function verify(
  publicKey: ED25519RawPublicKey,
  payload: Uint8Array,
  signature: ED25519RawSignature,
): boolean {
  const edOk = ed25519.verify(publicKey, payload, signature);
  return edOk;
}
