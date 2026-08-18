// src/types.ts

export type ED25519Signature = string;
export type ED25519PublicKey = string;
export type ED25519SecretKey = string;

export type ED25519RawSignature = Uint8Array;
export type ED25519RawPublicKey = Uint8Array;
export type ED25519RawSecretKey = Uint8Array;

export interface ED25519Keypair {
  public: ED25519RawPublicKey;
  secret: ED25519RawSecretKey;
}

export interface ED25519KeypairBase64 {
  privateKeyBase64: ED25519SecretKey;
  publicKeyBase64: ED25519PublicKey;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface NormalizedRequest {
  method: string;
  path: string;
  headers: Record<string, string | null>;
  rawBody: string; // "" for bodyless requests (GET, DELETE)
  params?: Record<string, string | number | boolean | null | undefined>;
}

export interface SignOptions {
  body?: unknown; // will be JSON.stringify'd if not already a string
  params?: Record<string, string | number | boolean | null | undefined>;
}

export type SignedHeaders = {
  "X-Signature-Timestamp": string;
  "X-Signature-Nonce": string;
  "X-Signature-KeyId": string;
  "X-Signature": string;
};

export type VerifyResult =
  | { valid: true; keyId: string; timestamp: number }
  | { valid: false; reason: VerifyFailureReason };

export type VerifyFailureReason =
  | "not_configured_for_verification"
  | "missing_signature_headers"
  | "timestamp_invalid"
  | "timestamp_out_of_window"
  | "replayed_nonce"
  | "unknown_key_id"
  | "signature_malformed"
  | "invalid_signature"
  // ed25519.verify() threw rather than returning false — malformed key
  // material at verify time, not a legitimate "signature didn't match".
  | "verification_error";

export interface NonceStore {
  /** Returns true if this nonce has already been seen. */
  has(nonce: string): Promise<boolean>;
  /** Records the nonce, valid for ttlSeconds. */
  put(nonce: string, ttlSeconds: number): Promise<void>;
}

export interface APIGuardConfig {
  mode: "sign" | "verify" | "both";
  /** Logical identity of this key, e.g. "desktop-v1", "webapp-v1". Required for sign mode. */
  keyId?: string;
  /**
   * Base64 of the full 64-byte @stablelib/ed25519 secretKey (seed[32] +
   * publicKey[32] concatenated — NOT a bare 32-byte seed). This is what
   * `ed25519.generateKeyPair().secretKey` produces and what
   * `APIGuard.generateKeyPair()` returns as `privateKeyBase64`. Required
   * for sign mode — there is no auto-generate fallback at init time by
   * design, so a missing key fails loudly at startup rather than silently
   * minting a throwaway identity your server doesn't trust.
   */
  privateKeyBase64?: string;
  /** keyId -> base64 32-byte Ed25519 public key. Required for verify mode. */
  publicKeys?: Record<string, string>;
  /** Allowed clock skew in ms. Default 90_000 (90s). */
  maxSkewMs?: number;
  /** Pluggable nonce/replay store. Defaults to an in-memory Map (single-instance only). */
  nonceStore?: NonceStore;
}


export interface FetchOptions extends Omit<RequestInit, "body"> {
  body?: any; // Accept object bodies to automatically JSON.stringify
  params?: Record<string, string>;
}