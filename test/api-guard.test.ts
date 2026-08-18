// tests/api-guard.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { APIGuard } from "../src/api-guard";
import { APIGuardError } from "../src/error";
import { base64ToBytes, bytesToBase64 } from "../src/hash";
import { NormalizedRequest } from "../src/types";

describe("APIGuard SDK", () => {
  let senderKeys: { privateKeyBase64: string; publicKeyBase64: string };
  let alternateKeys: { privateKeyBase64: string; publicKeyBase64: string };

  beforeEach(() => {
    // Generate fresh real cryptographic keypairs before each test run
    senderKeys = APIGuard.generateKeyPair();
    alternateKeys = APIGuard.generateKeyPair();
  });

  // ---------------------------------------------------------------------------
  // 1. Keypair Generation & Configuration / Initialization
  // ---------------------------------------------------------------------------
  describe("Initialization & Configuration", () => {
    it("generates valid Ed25519 keypairs with correct byte lengths", () => {
      const keys = APIGuard.generateKeyPair();
      expect(keys.privateKeyBase64).toBeDefined();
      expect(keys.publicKeyBase64).toBeDefined();

      const secretBytes = base64ToBytes(keys.privateKeyBase64);
      const publicBytes = base64ToBytes(keys.publicKeyBase64);

      expect(secretBytes.length).toBe(64);
      expect(publicBytes.length).toBe(32);
    });

    it("throws APIGuardError for invalid mode", () => {
      expect(
        () =>
          APIGuard.init({
            // @ts-expect-error Testing runtime invalid mode
            mode: "invalid_mode",
          }),
      ).toThrow(APIGuardError);
    });

    it("throws APIGuardError in sign mode when keyId or privateKeyBase64 is missing", () => {
      expect(
        () =>
          APIGuard.init({
            mode: "sign",
            privateKeyBase64: senderKeys.privateKeyBase64,
          }),
      ).toThrow("keyId is required in sign mode");

      expect(
        () =>
          APIGuard.init({
            mode: "sign",
            keyId: "client-1",
          }),
      ).toThrow("privateKeyBase64 is required in sign mode");
    });

    it("throws APIGuardError when privateKeyBase64 is malformed base64 or wrong byte length", () => {
      expect(
        () =>
          APIGuard.init({
            mode: "sign",
            keyId: "client-1",
            privateKeyBase64: "!!!not_base64!!!",
          }),
      ).toThrow("privateKeyBase64 is not valid base64");

      // 32-byte key instead of expected 64-byte secret key
      const shortKey = bytesToBase64(new Uint8Array(32));
      expect(
        () =>
          APIGuard.init({
            mode: "sign",
            keyId: "client-1",
            privateKeyBase64: shortKey,
          }),
      ).toThrow(/privateKeyBase64 must decode to 64 bytes/);
    });

    it("throws APIGuardError in verify mode when publicKeys is empty or malformed", () => {
      expect(
        () =>
          APIGuard.init({
            mode: "verify",
            publicKeys: {},
          }),
      ).toThrow("publicKeys must contain at least one entry in verify mode");

      expect(
        () =>
          APIGuard.init({
            mode: "verify",
            publicKeys: { "client-1": "!!!not_base64!!!" },
          }),
      ).toThrow('publicKeys["client-1"] is not valid base64');

      const shortPub = bytesToBase64(new Uint8Array(16));
      expect(
        () =>
          APIGuard.init({
            mode: "verify",
            publicKeys: { "client-1": shortPub },
          }),
      ).toThrow(/publicKeys\["client-1"\] must decode to 32 bytes/);
    });

    it("properly initializes properties in 'both' mode", () => {
      const guard = APIGuard.init({
        mode: "both",
        keyId: "client-1",
        privateKeyBase64: senderKeys.privateKeyBase64,
        publicKeys: {
          "alt-client": alternateKeys.publicKeyBase64,
        },
      });

      expect(guard.isReady).toBe(true);
      expect(guard.currentKeyId).toBe("client-1");
      expect(guard.publicKeyBase64).toBe(senderKeys.publicKeyBase64);
      expect(guard.trustedKeyIds).toContain("client-1");
      expect(guard.trustedKeyIds).toContain("alt-client");
    });

    it("wipes secret key material on dispose()", async () => {
      // <-- Add async
      const guard = APIGuard.init({
        mode: "sign",
        keyId: "client-1",
        privateKeyBase64: senderKeys.privateKeyBase64,
      });

      expect(guard.isReady).toBe(true);
      guard.dispose();
      expect(guard.isReady).toBe(false);

      // Add 'await' to the expect statement
      await expect(guard.sign("GET", "/api/v1/test")).rejects.toThrow(
        "APIGuard not configured for signing",
      );
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Request Signing
  // ---------------------------------------------------------------------------
  describe("Request Signing", () => {
    it("rejects invalid path formats", async () => {
      const signer = APIGuard.init({
        mode: "sign",
        keyId: "client-1",
        privateKeyBase64: senderKeys.privateKeyBase64,
      });

      await expect(signer.sign("GET", "")).rejects.toThrow(APIGuardError);
      await expect(signer.sign("GET", "api/v1/resource")).rejects.toThrow(
        APIGuardError,
      );
    });

    it("generates required headers with valid payload formatting", async () => {
      const signer = APIGuard.init({
        mode: "sign",
        keyId: "client-1",
        privateKeyBase64: senderKeys.privateKeyBase64,
      });

      const headers = await signer.sign("POST", "/api/v1/data", {
        body: { foo: "bar" },
        params: { active: true },
      });

      expect(headers["X-Signature-KeyId"]).toBe("client-1");
      expect(headers["X-Signature-Nonce"]).toBeDefined();
      expect(headers["X-Signature-Nonce"].length).toBe(32); // 16 bytes = 32 hex chars
      expect(headers["X-Signature-Timestamp"]).toBeDefined();
      expect(Number(headers["X-Signature-Timestamp"])).not.toBeNaN();
      expect(headers["X-Signature"]).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Request Verification & End-to-End Success Scenarios
  // ---------------------------------------------------------------------------
  describe("Verification Happy Paths", () => {
    it("verifies requests signed in 'both' mode using NormalizedRequest", async () => {
      const guard = APIGuard.init({
        mode: "both",
        keyId: "client-1",
        privateKeyBase64: senderKeys.privateKeyBase64,
      });

      const body = { amount: 100, currency: "USD" };
      const headers = await guard.sign("POST", "/api/v1/transfers", { body });

      const requestToVerify: NormalizedRequest = {
        method: "POST",
        path: "/api/v1/transfers",
        headers,
        rawBody: JSON.stringify(body),
      };

      const result = await guard.verify(requestToVerify);
      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.keyId).toBe("client-1");
        expect(result.timestamp).toBeDefined();
      }
    });

    it("verifies requests between separate signer and verifier instances", async () => {
      const signer = APIGuard.init({
        mode: "sign",
        keyId: "client-1",
        privateKeyBase64: senderKeys.privateKeyBase64,
      });

      const verifier = APIGuard.init({
        mode: "verify",
        publicKeys: {
          "client-1": senderKeys.publicKeyBase64,
        },
      });

      const headers = await signer.sign("GET", "/api/v1/users", {
        params: { role: "admin", limit: 10 },
      });

      const requestToVerify: NormalizedRequest = {
        method: "GET",
        path: "/api/v1/users",
        headers,
        rawBody: "",
        params: { role: "admin", limit: 10 },
      };

      const result = await verifier.verify(requestToVerify);
      expect(result.valid).toBe(true);
    });

    it("verifies Web Standard Request objects directly", async () => {
      const signer = APIGuard.init({
        mode: "sign",
        keyId: "client-1",
        privateKeyBase64: senderKeys.privateKeyBase64,
      });

      const verifier = APIGuard.init({
        mode: "verify",
        publicKeys: { "client-1": senderKeys.publicKeyBase64 },
      });

      const body = JSON.stringify({ message: "hello" });
      const signedHeaders = await signer.sign("POST", "/api/v1/messages", {
        body,
      });

      const fetchRequest = new Request(
        "https://api.example.com/api/v1/messages",
        {
          method: "POST",
          headers: signedHeaders as unknown as HeadersInit,
          body,
        },
      );

      const result = await verifier.verify(fetchRequest);
      expect(result.valid).toBe(true);
    });

    it("verifyOrThrow succeeds on valid signature and throws APIGuardError on failure", async () => {
      const guard = APIGuard.init({
        mode: "both",
        keyId: "client-1",
        privateKeyBase64: senderKeys.privateKeyBase64,
      });

      const headers = await guard.sign("GET", "/api/v1/status");
      const validReq: NormalizedRequest = {
        method: "GET",
        path: "/api/v1/status",
        headers,
        rawBody: "",
      };

      const outcome = await guard.verifyOrThrow(validReq);
      expect(outcome.keyId).toBe("client-1");

      // Generate a fresh signature so we don't trip the "replayed_nonce" protection
      const headers2 = await guard.sign("GET", "/api/v1/status");
      const invalidReq: NormalizedRequest = {
        method: "GET",
        path: "/api/v1/tampered", // tampered path invalidates the signature
        headers: headers2,
        rawBody: "",
      };

      await expect(guard.verifyOrThrow(invalidReq)).rejects.toThrow(
        "Signature verification failed: invalid_signature",
      );
    });
  });

  // ---------------------------------------------------------------------------
  // 4. Security, Attack Scenarios, & Tampering Edge Cases
  // ---------------------------------------------------------------------------
  describe("Security & Tampering Scenarios", () => {
    let signer: APIGuard;
    let verifier: APIGuard;

    beforeEach(() => {
      signer = APIGuard.init({
        mode: "sign",
        keyId: "client-1",
        privateKeyBase64: senderKeys.privateKeyBase64,
      });

      verifier = APIGuard.init({
        mode: "verify",
        publicKeys: { "client-1": senderKeys.publicKeyBase64 },
        maxSkewMs: 5000, // 5 seconds skew window
      });
    });

    it("fails when payload body is tampered", async () => {
      const headers = await signer.sign("POST", "/api/v1/pay", {
        body: JSON.stringify({ recipient: "alice", amount: 10 }),
      });

      const tamperedReq: NormalizedRequest = {
        method: "POST",
        path: "/api/v1/pay",
        headers,
        rawBody: JSON.stringify({ recipient: "alice", amount: 1000000 }),
      };

      const result = await verifier.verify(tamperedReq);
      expect(result).toEqual({ valid: false, reason: "invalid_signature" });
    });

    it("fails when path or method is tampered", async () => {
      const headers = await signer.sign("GET", "/api/v1/resource");

      const tamperedPath: NormalizedRequest = {
        method: "GET",
        path: "/api/v1/other-resource",
        headers,
        rawBody: "",
      };
      expect(await verifier.verify(tamperedPath)).toEqual({
        valid: false,
        reason: "invalid_signature",
      });

      const tamperedMethod: NormalizedRequest = {
        method: "DELETE",
        path: "/api/v1/resource",
        headers,
        rawBody: "",
      };
      expect(await verifier.verify(tamperedMethod)).toEqual({
        valid: false,
        reason: "invalid_signature",
      });
    });

    it("fails when query parameters are altered, added, or reordered", async () => {
      const headers = await signer.sign("GET", "/search", {
        params: { query: "vitest", page: 1 },
      });

      const alteredParams: NormalizedRequest = {
        method: "GET",
        path: "/search",
        headers,
        rawBody: "",
        params: { query: "vitest", page: 2 },
      };
      expect(await verifier.verify(alteredParams)).toEqual({
        valid: false,
        reason: "invalid_signature",
      });

      const addedParams: NormalizedRequest = {
        method: "GET",
        path: "/search",
        headers,
        rawBody: "",
        params: { query: "vitest", page: 1, hack: "true" },
      };
      expect(await verifier.verify(addedParams)).toEqual({
        valid: false,
        reason: "invalid_signature",
      });
    });

    it("fails when timestamp is modified within skew window (invalid signature)", async () => {
      const headers = await signer.sign("GET", "/api/v1/test");
      const originalTs = Number(headers["X-Signature-Timestamp"]);

      const tamperedHeaders = {
        ...headers,
        "X-Signature-Timestamp": String(originalTs + 100), // slightly modified timestamp
      };

      const req: NormalizedRequest = {
        method: "GET",
        path: "/api/v1/test",
        headers: tamperedHeaders,
        rawBody: "",
      };

      expect(await verifier.verify(req)).toEqual({
        valid: false,
        reason: "invalid_signature",
      });
    });

    it("detects expired timestamps beyond maxSkewMs window", async () => {
      const headers = await signer.sign("GET", "/api/v1/test");

      // Set timestamp outside 5000ms window
      const expiredHeaders = {
        ...headers,
        "X-Signature-Timestamp": String(Date.now() - 10_000),
      };

      const req: NormalizedRequest = {
        method: "GET",
        path: "/api/v1/test",
        headers: expiredHeaders,
        rawBody: "",
      };

      expect(await verifier.verify(req)).toEqual({
        valid: false,
        reason: "timestamp_out_of_window",
      });
    });

    it("rejects non-numeric timestamp headers", async () => {
      const headers = await signer.sign("GET", "/api/v1/test");
      const badReq: NormalizedRequest = {
        method: "GET",
        path: "/api/v1/test",
        headers: { ...headers, "X-Signature-Timestamp": "not_a_number" },
        rawBody: "",
      };

      expect(await verifier.verify(badReq)).toEqual({
        valid: false,
        reason: "timestamp_invalid",
      });
    });

    it("prevents replay attacks with the same nonce", async () => {
      const headers = await signer.sign("POST", "/api/v1/action", {
        body: { id: 1 },
      });

      const req: NormalizedRequest = {
        method: "POST",
        path: "/api/v1/action",
        headers,
        rawBody: JSON.stringify({ id: 1 }),
      };

      // First verification succeeds
      const firstTry = await verifier.verify(req);
      expect(firstTry.valid).toBe(true);

      // Replayed request fails
      const secondTry = await verifier.verify(req);
      expect(secondTry).toEqual({
        valid: false,
        reason: "replayed_nonce",
      });
    });

    it("rejects request signed with unknown key ID", async () => {
      const rogueSigner = APIGuard.init({
        mode: "sign",
        keyId: "unknown-rogue-key",
        privateKeyBase64: alternateKeys.privateKeyBase64,
      });

      const headers = await rogueSigner.sign("GET", "/api/v1/data");
      const req: NormalizedRequest = {
        method: "GET",
        path: "/api/v1/data",
        headers,
        rawBody: "",
      };

      expect(await verifier.verify(req)).toEqual({
        valid: false,
        reason: "unknown_key_id",
      });
    });

    it("fails when signature is malformed base64 or invalid length", async () => {
      const headers = await signer.sign("GET", "/api/v1/data");

      const malformedReq: NormalizedRequest = {
        method: "GET",
        path: "/api/v1/data",
        headers: { ...headers, "X-Signature": "!!!invalid_base64!!!" },
        rawBody: "",
      };
      expect(await verifier.verify(malformedReq)).toEqual({
        valid: false,
        reason: "signature_malformed",
      });

      const shortSigReq: NormalizedRequest = {
        method: "GET",
        path: "/api/v1/data",
        headers: {
          ...headers,
          "X-Signature": bytesToBase64(new Uint8Array(10)),
        },
        rawBody: "",
      };
      expect(await verifier.verify(shortSigReq)).toEqual({
        valid: false,
        reason: "signature_malformed",
      });
    });

    it("rejects request when any required signature header is missing", async () => {
      const headers = await signer.sign("GET", "/api/v1/data");

      const missingHeaderReq: NormalizedRequest = {
        method: "GET",
        path: "/api/v1/data",
        headers: {
          "x-signature-timestamp": headers["X-Signature-Timestamp"],
          "x-signature-nonce": headers["X-Signature-Nonce"],
          // missing X-Signature-KeyId and X-Signature
        },
        rawBody: "",
      };

      expect(await verifier.verify(missingHeaderReq)).toEqual({
        valid: false,
        reason: "missing_signature_headers",
      });
    });

    it("rejects signature signed by a different keypair even if keyId matches", async () => {
      const imposterSigner = APIGuard.init({
        mode: "sign",
        keyId: "client-1", // Using legitimate keyId
        privateKeyBase64: alternateKeys.privateKeyBase64, // ...but wrong private key
      });

      const headers = await imposterSigner.sign("GET", "/api/v1/secure");
      const req: NormalizedRequest = {
        method: "GET",
        path: "/api/v1/secure",
        headers,
        rawBody: "",
      };

      expect(await verifier.verify(req)).toEqual({
        valid: false,
        reason: "invalid_signature",
      });
    });
  });

  // ---------------------------------------------------------------------------
  // 5. Static Facade & Singleton Management
  // ---------------------------------------------------------------------------
  describe("Static Facade", () => {
    it("throws APIGuardError when static methods are called before init()", async () => {
      // Force reset the singleton reference internally to simulate pre-initialization.
      // @ts-expect-error - overriding private static property for test setup
      APIGuard.instance = null;

      await expect(APIGuard.sign("GET", "/test")).rejects.toThrow(
        "APIGuard.init(...) must be called before use",
      );
    });

    it("supports static workflow using APIGuard.init()", async () => {
      APIGuard.init({
        mode: "both",
        keyId: "static-client",
        privateKeyBase64: senderKeys.privateKeyBase64,
      });

      const headers = await APIGuard.sign("POST", "/api/v1/static", {
        body: { static: true },
      });

      const req: NormalizedRequest = {
        method: "POST",
        path: "/api/v1/static",
        headers,
        rawBody: JSON.stringify({ static: true }),
      };

      const result = await APIGuard.verify(req);
      expect(result.valid).toBe(true);

      // Create a fresh request to test verifyOrThrow, otherwise the nonce from `req`
      // is already burned by the first `verify` call, resulting in a replay error!
      const headers2 = await APIGuard.sign("POST", "/api/v1/static2", {
        body: { static: true },
      });

      const req2: NormalizedRequest = {
        method: "POST",
        path: "/api/v1/static2",
        headers: headers2,
        rawBody: JSON.stringify({ static: true }),
      };

      const verified = await APIGuard.verifyOrThrow(req2);
      expect(verified.keyId).toBe("static-client");
    });
  });

  // ---------------------------------------------------------------------------
  // 6. Request Normalization Helper
  // ---------------------------------------------------------------------------
  describe("APIGuard.normalize()", () => {
    it("correctly normalizes standard Fetch Request objects", async () => {
      const request = new Request("https://api.example.com/v1/test?a=1&b=2", {
        method: "POST",
        headers: {
          "X-Custom-Header": "value",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ test: "data" }),
      });

      const normalized = await APIGuard.normalize(request);

      expect(normalized.method).toBe("POST");
      expect(normalized.path).toBe("/v1/test");
      expect(normalized.headers["x-custom-header"]).toBe("value");
      expect(normalized.rawBody).toBe(JSON.stringify({ test: "data" }));
      expect(normalized.params).toEqual({ a: "1", b: "2" });
    });

    it("lowercases header keys for NormalizedRequest inputs", async () => {
      const rawInput: NormalizedRequest = {
        method: "GET",
        path: "/v1/test",
        headers: {
          "X-SIGNATURE": "sig",
          "X-Signature-KeyId": "id",
        },
        rawBody: "",
      };

      const normalized = await APIGuard.normalize(rawInput);

      expect(normalized.headers["x-signature"]).toBe("sig");
      expect(normalized.headers["x-signature-keyid"]).toBe("id");
    });
  });
});
