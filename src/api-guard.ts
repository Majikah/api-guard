// src/api-guard.ts

import {
  generateEd25519Keypair,
  getPublicKeyFromSecretKey,
  sign as ed25519Sign,
  verify as ed25519Verify,
  secureWipe,
  PUBLIC_KEY_LENGTH,
  SECRET_KEY_LENGTH,
  SIGNATURE_LENGTH,
} from "./crypto";
import { APIGuardError } from "./error";
import { base64ToBytes, bytesToBase64, bytesToHex, sha256Hex } from "./hash";
import { buildSigningPayload, canonicalizeParams } from "./payload";
import {
  APIGuardConfig,
  ED25519KeypairBase64,
  HttpMethod,
  NonceStore,
  NormalizedRequest,
  SignedHeaders,
  SignOptions,
  VerifyResult,
} from "./types";

// ---------------------------------------------------------------------------
// Default in-memory nonce store (fine for a single Worker isolate / dev;
// swap in a KV/Redis-backed adapter for multi-instance deployments).
// ---------------------------------------------------------------------------

class InMemoryNonceStore implements NonceStore {
  private seen = new Map<string, number>(); // nonce -> expiresAt (ms)

  async has(nonce: string): Promise<boolean> {
    this.sweep();
    return this.seen.has(nonce);
  }

  async put(nonce: string, ttlSeconds: number): Promise<void> {
    this.seen.set(nonce, Date.now() + ttlSeconds * 1000);
  }

  private sweep() {
    const now = Date.now();
    for (const [nonce, expiresAt] of this.seen) {
      if (expiresAt <= now) this.seen.delete(nonce);
    }
  }
}

function randomNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

// ---------------------------------------------------------------------------
// APIGuard
// ---------------------------------------------------------------------------

/**
 * APIGuard
 * ---
 * Environment-agnostic Ed25519 request signing & verification.
 * Works identically in: browser, Node.js, Cloudflare Workers, Next.js.
 */
export class APIGuard {
  private static instance: APIGuard | null = null;

  private mode: "sign" | "verify" | "both";
  private keyId?: string;
  private secretKey?: Uint8Array; // sensitive — wiped via dispose()/finally blocks
  private publicKey?: Uint8Array; // this instance's own pubkey, sign mode
  private publicKeyRegistry: Map<string, Uint8Array> = new Map();
  private maxSkewMs: number;
  private nonceStore: NonceStore;

  private constructor(config: APIGuardConfig) {
    if (
      config.mode !== "sign" &&
      config.mode !== "verify" &&
      config.mode !== "both"
    ) {
      throw new APIGuardError(`Invalid mode: ${String(config.mode)}`);
    }

    this.mode = config.mode;
    this.maxSkewMs = config.maxSkewMs ?? 90_000;
    this.nonceStore = config.nonceStore ?? new InMemoryNonceStore();

    if (config.mode === "sign" || config.mode === "both") {
      if (!config.keyId || config.keyId.trim().length === 0) {
        throw new APIGuardError("keyId is required in sign mode");
      }
      if (!config.privateKeyBase64) {
        throw new APIGuardError("privateKeyBase64 is required in sign mode");
      }

      this.keyId = config.keyId;

      let decoded: Uint8Array;
      try {
        decoded = base64ToBytes(config.privateKeyBase64);
      } catch {
        throw new APIGuardError("privateKeyBase64 is not valid base64");
      }

      if (decoded.length !== SECRET_KEY_LENGTH) {
        secureWipe(decoded);
        throw new APIGuardError(
          `privateKeyBase64 must decode to ${SECRET_KEY_LENGTH} bytes ` +
            `(the full stablelib secretKey — seed + public key), got ${decoded.length}`,
        );
      }

      this.secretKey = decoded;
      this.publicKey = getPublicKeyFromSecretKey(this.secretKey);
    }

    if (config.mode === "verify" || config.mode === "both") {
      const entries = Object.entries(config.publicKeys ?? {});

      if (config.mode === "verify" && entries.length === 0) {
        throw new APIGuardError(
          "publicKeys must contain at least one entry in verify mode",
        );
      }

      for (const [id, pub] of entries) {
        let decoded: Uint8Array;
        try {
          decoded = base64ToBytes(pub);
        } catch {
          throw new APIGuardError(`publicKeys["${id}"] is not valid base64`);
        }
        if (decoded.length !== PUBLIC_KEY_LENGTH) {
          throw new APIGuardError(
            `publicKeys["${id}"] must decode to ${PUBLIC_KEY_LENGTH} bytes, got ${decoded.length}`,
          );
        }
        this.publicKeyRegistry.set(id, decoded);
      }

      // "both" mode: also trust its own public key under its own keyId.
      if (config.mode === "both" && this.keyId && this.publicKey) {
        this.publicKeyRegistry.set(this.keyId, this.publicKey);
      }
    }
  }

  // -- Static facade -----------------------------------------------------
  // `init()` is a factory: each call returns a brand-new, independent
  // instance and ALSO points the static facade (APIGuard.sign/verify) at
  // it. Critically, it does NOT touch any previously-created instance —
  // calling init() again to create a `verifier` does not affect an
  // earlier `signer` you're still holding a reference to. This is what
  // lets one process hold several independent guards (e.g. a `signer`
  // and a `verifier`, or several signers under different keyIds) by just
  // calling `APIGuard.init()` multiple times and keeping each result.
  //
  // Because instances are never auto-disposed, YOU own their lifetime:
  // call `guard.dispose()` yourself once you're done with a specific
  // instance (e.g. during key rotation) to wipe its key material instead
  // of leaving it for the GC.

  static init(config: APIGuardConfig): APIGuard {
    APIGuard.instance = new APIGuard(config);
    return APIGuard.instance;
  }

  private static getInstance(): APIGuard {
    if (!APIGuard.instance) {
      throw new APIGuardError("APIGuard.init(...) must be called before use");
    }
    return APIGuard.instance;
  }

  static async sign(
    method: HttpMethod | string,
    path: string,
    opts: SignOptions = {},
  ): Promise<SignedHeaders> {
    return APIGuard.getInstance().sign(method, path, opts);
  }

  static async verify(
    input: Request | NormalizedRequest,
  ): Promise<VerifyResult> {
    return APIGuard.getInstance().verify(input);
  }

  static async verifyOrThrow(
    input: Request | NormalizedRequest,
  ): Promise<{ keyId: string; timestamp: number }> {
    return APIGuard.getInstance().verifyOrThrow(input);
  }

  static generateKeyPair(): ED25519KeypairBase64 {
    const keypair = generateEd25519Keypair();
    const result = {
      privateKeyBase64: bytesToBase64(keypair.secret),
      publicKeyBase64: bytesToBase64(keypair.public),
    };
    // The caller now only needs the base64 strings going forward — wipe
    // the raw copy rather than leaving it to the GC's schedule.
    secureWipe(keypair.secret);
    return result;
  }

  /** Wipes this instance's private key material. Call when rotating keys
   *  or tearing down (hot-reload in dev, explicit shutdown, etc). */
  dispose(): void {
    secureWipe(this.secretKey);
    this.secretKey = undefined;
  }

  // -- Getters -------------------------------------------------------------

  get isReady(): boolean {
    return this.mode === "verify"
      ? this.publicKeyRegistry.size > 0
      : Boolean(this.secretKey);
  }

  get currentKeyId(): string | undefined {
    return this.keyId;
  }

  /** Safe to expose/distribute — this is the public half only. */
  get publicKeyBase64(): string | undefined {
    return this.publicKey ? bytesToBase64(this.publicKey) : undefined;
  }

  get trustedKeyIds(): string[] {
    return [...this.publicKeyRegistry.keys()];
  }

  // -- Signing ---------------------------------------------------------------

  async sign(
    method: HttpMethod | string,
    path: string,
    opts: SignOptions = {},
  ): Promise<SignedHeaders> {
    if (!this.secretKey || !this.keyId) {
      throw new APIGuardError("APIGuard not configured for signing");
    }
    if (!path || !path.startsWith("/")) {
      throw new APIGuardError(
        `path must be a non-empty string starting with "/", got: ${path}`,
      );
    }

    const timestamp = Date.now();
    const nonce = randomNonce();
    const body =
      opts.body === undefined
        ? ""
        : typeof opts.body === "string"
          ? opts.body
          : JSON.stringify(opts.body);

    const canonicalParams = canonicalizeParams(opts.params);
    const payload = buildSigningPayload({
      keyId: this.keyId,
      timestamp,
      nonce,
      method,
      path,
      bodyHash: sha256Hex(body),
      paramsHash:
        canonicalParams === undefined ? undefined : sha256Hex(canonicalParams),
    });

    // Clone before signing and wipe the clone immediately after — the
    // long-lived key stays in this.secretKey (needed for future calls),
    // but no transient copy of it lingers in memory past this call.
    let secretKeyClone: Uint8Array | undefined;
    try {
      secretKeyClone = this.secretKey.slice();
      const signature = ed25519Sign(secretKeyClone, payload);
      return {
        "X-Signature-Timestamp": String(timestamp),
        "X-Signature-Nonce": nonce,
        "X-Signature-KeyId": this.keyId,
        "X-Signature": bytesToBase64(signature),
      };
    } finally {
      if (secretKeyClone) {
        secureWipe(secretKeyClone);
        secretKeyClone = undefined;
      }
    }
  }

  // -- Verification ------------------------------------------------------

  async verify(input: Request | NormalizedRequest): Promise<VerifyResult> {
    if (this.publicKeyRegistry.size === 0) {
      return { valid: false, reason: "not_configured_for_verification" };
    }

    const normalized = await APIGuard.normalize(input);

    const timestampHeader = normalized.headers["x-signature-timestamp"];
    const nonce = normalized.headers["x-signature-nonce"];
    const keyId = normalized.headers["x-signature-keyid"];
    const signatureB64 = normalized.headers["x-signature"];

    if (!timestampHeader || !nonce || !keyId || !signatureB64) {
      return { valid: false, reason: "missing_signature_headers" };
    }

    const timestamp = Number(timestampHeader);
    if (!Number.isFinite(timestamp)) {
      return { valid: false, reason: "timestamp_invalid" };
    }
    if (Math.abs(Date.now() - timestamp) > this.maxSkewMs) {
      return { valid: false, reason: "timestamp_out_of_window" };
    }

    if (await this.nonceStore.has(nonce)) {
      return { valid: false, reason: "replayed_nonce" };
    }

    const publicKey = this.publicKeyRegistry.get(keyId);
    if (!publicKey) {
      return { valid: false, reason: "unknown_key_id" };
    }

    let signature: Uint8Array;
    try {
      signature = base64ToBytes(signatureB64);
    } catch {
      return { valid: false, reason: "signature_malformed" };
    }
    if (signature.length !== SIGNATURE_LENGTH) {
      return { valid: false, reason: "signature_malformed" };
    }

    const canonicalParams = canonicalizeParams(normalized.params);
    const payload = buildSigningPayload({
      keyId,
      timestamp,
      nonce,
      method: normalized.method,
      path: normalized.path,
      bodyHash: sha256Hex(normalized.rawBody),
      paramsHash:
        canonicalParams === undefined ? undefined : sha256Hex(canonicalParams),
    });

    let edOk: boolean;
    try {
      edOk = ed25519Verify(publicKey, payload, signature);
    } catch (e) {
      console.error(e);
      return { valid: false, reason: "verification_error" };
    }

    if (!edOk) {
      return { valid: false, reason: "invalid_signature" };
    }

    // Only record the nonce once the signature is confirmed genuine —
    // an attacker spamming garbage signatures shouldn't be able to burn
    // through/pollute the replay cache with nonces that were never valid.
    await this.nonceStore.put(nonce, Math.ceil(this.maxSkewMs / 1000));

    return { valid: true, keyId, timestamp };
  }

  /** Convenience wrapper for callers who prefer throw-on-failure. */
  async verifyOrThrow(
    input: Request | NormalizedRequest,
  ): Promise<{ keyId: string; timestamp: number }> {
    const result = await this.verify(input);
    if (!result.valid) {
      throw new APIGuardError(
        `Signature verification failed: ${result.reason}`,
      );
    }
    return { keyId: result.keyId, timestamp: result.timestamp };
  }

  // -- Request normalization ----------------------------------------------
  // Accepts either a Fetch API Request (Workers, Next.js Route Handlers,
  // browser) or an already-normalized object (Node/Express, where you
  // read the raw body yourself before this point — Node's IncomingMessage
  // stream can't be read twice, so we can't accept it directly here).

  static async normalize(
    input: Request | NormalizedRequest,
  ): Promise<NormalizedRequest> {
    if (APIGuard.isFetchRequest(input)) {
      const url = new URL(input.url);
      const rawBody =
        input.method === "GET" || input.method === "HEAD"
          ? ""
          : await input.clone().text();
      const headers: Record<string, string | null> = {};
      input.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });
      const params: Record<string, string> = {};
      url.searchParams.forEach((value, key) => {
        params[key] = value;
      });
      return {
        method: input.method,
        path: url.pathname,
        headers,
        rawBody,
        params: Object.keys(params).length > 0 ? params : undefined,
      };
    }

    // Already normalized — just lowercase headers defensively.
    const headers: Record<string, string | null> = {};
    for (const [k, v] of Object.entries(input.headers)) {
      headers[k.toLowerCase()] = v;
    }
    return { ...input, headers };
  }

  private static isFetchRequest(input: unknown): input is Request {
    return (
      typeof input === "object" &&
      input !== null &&
      "method" in input &&
      "headers" in input &&
      typeof (input as Request).clone === "function"
    );
  }
}

// Freeze instance methods
Object.freeze(APIGuard.prototype);
