# APIGuard


[![Developed by Zelijah](https://img.shields.io/badge/Developed%20by-Zelijah-red?logo=github&logoColor=white)](https://www.thezelijah.world) ![GitHub Sponsors](https://img.shields.io/github/sponsors/jedlsf?style=plastic&label=Sponsors&link=https%3A%2F%2Fgithub.com%2Fsponsors%2Fjedlsf)


**Environment-agnostic Ed25519 request signing & verification.**

APIGuard is a lightweight SDK for securing API communications. It uses Ed25519 cryptography to sign requests and verify their integrity. Built to run anywhere—Node.js, Cloudflare Workers, Next.js, and the browser—it natively supports standard Web `Request` objects while protecting your API against payload tampering and replay attacks.

![npm](https://img.shields.io/npm/v/@majikah/api-guard) ![npm downloads](https://img.shields.io/npm/dm/@majikah/api-guard) ![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)


## Features

- 🔒 **Ed25519 Cryptography**: Fast, highly secure request signing via [`@stablelib/ed25519`](https://github.com/StableLib/stablelib) — pure JS/TS, no native bindings, identical behavior across every environment.
- 🛡️ **Built-in Replay Protection**: Nonce tracking ensures a captured request cannot be re-used.
- ⏱️ **Timestamp Skew Validation**: Rejects requests that are too old to prevent delayed attacks.
- 🌐 **Environment Agnostic**: Works perfectly in edge runtimes (Cloudflare, Vercel), Node.js, and browsers.
- 📦 **Fetch API Native**: Directly verifies standard Web `Request` objects without manual parsing.
- 🧹 **Memory Safe**: Includes `.dispose()` methods and secure memory wiping for sensitive key material.

## Dependencies

APIGuard has two minimal, audited runtime dependencies — no framework or environment-specific bindings:

- [`@stablelib/ed25519`](https://www.npmjs.com/package/@stablelib/ed25519) — signing/verification
- [`@stablelib/sha256`](https://www.npmjs.com/package/@stablelib/sha256) — content hashing

Both are pure TypeScript with no native code, which is precisely what makes identical behavior across browser, Node, and Workers possible.

---

## Installation

```bash
npm install @majikah/api-guard
# or
yarn add @majikah/api-guard
# or
pnpm add @majikah/api-guard
```

---

## Quick Start

### 1. Generate Keypairs
First, generate a secure Ed25519 keypair. You only need to do this once (or when rotating keys).

```typescript
import { APIGuard } from "@majikah/api-guard";

const keys = APIGuard.generateKeyPair();
console.log("Private Key:", keys.privateKeyBase64); // Store securely (e.g., .env) — never commit or expose client-side
console.log("Public Key:", keys.publicKeyBase64);   // Share with the verifier
```

### 2. Sign a Request (Client)
Use `sign` mode to generate cryptographic headers for your API request.

```typescript
import { APIGuard } from "@majikah/api-guard";

const signer = APIGuard.init({
  mode: "sign",
  keyId: "client-1",
  privateKeyBase64: process.env.CLIENT_PRIVATE_KEY,
});

const body = { amount: 100, currency: "PHP" };

const headers = await signer.sign("POST", "/api/v1/transfers", {
  body: body
});

const response = await fetch("https://api.example.com/api/v1/transfers", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    ...headers // Injects X-Signature, X-Signature-Timestamp, X-Signature-Nonce, X-Signature-KeyId
  },
  body: JSON.stringify(body)
});
```

**Signing a GET request with query params** — params are signed separately from the body, so this works the same way:

```typescript
const headers = await signer.sign("GET", "/api/v1/users", {
  params: { role: "admin", limit: 10 },
});

const url = new URL("https://api.example.com/api/v1/users");
url.searchParams.set("role", "admin");
url.searchParams.set("limit", "10");

const response = await fetch(url, { headers });
```

### 3. Verify a Request (Server / Edge)
Use `verify` mode to validate the request payload, timestamp, and signature.

```typescript
import { APIGuard } from "@majikah/api-guard";

const verifier = APIGuard.init({
  mode: "verify",
  publicKeys: {
    "client-1": process.env.CLIENT_PUBLIC_KEY,
  },
});

export async function POST(request: Request) {
  // Pass the raw Fetch Request directly to APIGuard — Workers and
  // Next.js Route Handlers both use the Fetch Request type natively.
  const result = await verifier.verify(request);

  if (!result.valid) {
    return new Response(`Unauthorized: ${result.reason}`, { status: 401 });
  }

  console.log(`Verified request from client: ${result.keyId}`);
  return new Response("Success", { status: 200 });
}
```

---

## How It Works

Each signed request produces a canonical, domain-separated payload before signing — not just the raw body:

```
domain prefix ("apiguard-sig-v1:") + JSON{
  v:  signature scheme version
  id: keyId
  ts: timestamp (ms)
  n:  nonce
  m:  HTTP method
  p:  path
  bh: sha256(body) — hex
  ph: sha256(canonicalized query params) — hex, omitted entirely if no params
}
```

This is what actually gets signed with Ed25519. A few properties this gives you:

- **Domain separation**: the fixed prefix means an APIGuard signature can never be confused with a signature from a different scheme, even over identical underlying bytes.
- **Tamper-evidence on the timestamp**: because the timestamp is inside the signed payload (not a separate unauthenticated header), it can't be altered without invalidating the signature — this is what makes the skew check trustworthy.
- **Replay protection**: the nonce is likewise inside the signed payload, and the server tracks seen nonces for the duration of the skew window (see `NonceStore` below).
- **Byte-exact body hashing**: the body is hashed as raw bytes, not re-serialized JSON — see the [Express integration note](#using-nodejs-express--fastify) below for why this matters.

---

## Advanced Usage

### The Static Facade
If you only need a single APIGuard configuration throughout your app, use the static facade instead of managing an instance reference.

```typescript
import { APIGuard } from "@majikah/api-guard";

// 1. Initialize once at app startup
APIGuard.init({
  mode: "both",
  keyId: "my-service",
  privateKeyBase64: process.env.PRIVATE_KEY,
  publicKeys: {
    "trusted-service": process.env.TRUSTED_PUBLIC_KEY
  }
});

// 2. Use anywhere statically
const headers = await APIGuard.sign("GET", "/api/data");
const result = await APIGuard.verify(incomingRequest);
```

> **Note:** `APIGuard.init()` is a factory — each call returns a new, independent instance and points the static facade at it, but it does **not** dispose any previously-created instance. If your app holds onto multiple instances (e.g. a `signer` and a `verifier`, or several keys during rotation), each remains fully functional after later `init()` calls. This means *you* own instance lifetime — call `guard.dispose()` explicitly on an instance once you're done with it. See [Security Best Practices](#security-best-practices).

### Using Node.js (Express / Fastify)
Standard Node.js `IncomingMessage` requests aren't Web `Request` objects, and their streams can only be read once, so pass a `NormalizedRequest` object instead of the raw `req`.

**Two things need care here**, both of which are easy to get wrong:

1. **Never re-serialize a parsed body.** The client signs the *exact bytes it sent*. If you parse the body with `express.json()` and then do `JSON.stringify(req.body)` to hand back to APIGuard, you are hashing a *reconstruction* of the body, not the original — key ordering, whitespace, and number formatting can differ even when nothing was tampered with, causing verification to fail unpredictably. Capture the raw body text before parsing instead.
2. **`req.headers` values can be arrays.** Node's `IncomingHttpHeaders` allows `string | string[] | undefined` per header (repeated headers), which doesn't match `NormalizedRequest`'s `string | null`. Map explicitly.

```typescript
import express from "express";

const app = express();

// Capture the raw body BEFORE any JSON parsing middleware runs.
app.use(express.text({ type: "*/*" }));

function toNormalizedHeaders(
  headers: Record<string, string | string[] | undefined>
): Record<string, string | null> {
  const out: Record<string, string | null> = {};
  for (const [key, value] of Object.entries(headers)) {
    out[key] = Array.isArray(value) ? value[0] ?? null : value ?? null;
  }
  return out;
}

app.post("/api/webhook", async (req, res) => {
  const rawBody = req.body as string; // exact bytes as sent, thanks to express.text()

  const normalized = {
    method: req.method,
    path: req.path,
    headers: toNormalizedHeaders(req.headers), // APIGuard lowercases keys internally regardless
    rawBody,
    params: req.query as Record<string, string>,
  };

  const { valid, reason } = await verifier.verify(normalized);
  if (!valid) return res.status(401).send(reason);

  const parsedBody = JSON.parse(rawBody); // safe to parse now that it's verified
  res.send("OK");
});
```

### Throwing Errors Automatically
If you prefer a try/catch workflow rather than checking a boolean result, use `verifyOrThrow`:

```typescript
try {
  const { keyId } = await APIGuard.verifyOrThrow(request);
  console.log("Verified:", keyId);
} catch (error) {
  console.error("Verification failed:", error.message);
}
```

### Custom Nonce Store (Distributed Environments)
By default, APIGuard uses an in-memory `NonceStore` to prevent replay attacks. If you're running multiple isolated instances (serverless functions, Node.js clusters, multiple Worker isolates), use a distributed store like Redis or Cloudflare KV instead — an in-memory store can't see nonces recorded by a different instance/isolate.

```typescript
const redisNonceStore = {
  async has(nonce: string) {
    return (await redis.exists(`nonce:${nonce}`)) === 1;
  },
  async put(nonce: string, ttlSeconds: number) {
    await redis.setex(`nonce:${nonce}`, ttlSeconds, "1");
  }
};

const verifier = APIGuard.init({
  mode: "verify",
  publicKeys: { /* ... */ },
  nonceStore: redisNonceStore
});
```

> **Note:** the TTL passed to `put()` is always derived from `maxSkewMs` (rounded up to the nearest second) — there's no separate nonce-TTL setting. If you lower `maxSkewMs`, the nonce cache window shrinks with it automatically.

---

## Handling Verification Failures

`verify()` never throws for an invalid signature — it returns a discriminated result so you can log or branch on *why* a request was rejected:

```typescript
const result = await verifier.verify(request);
if (!result.valid) {
  console.warn("Rejected request:", result.reason);
}
```

| `reason`                          | Meaning                                                                 |
| --------------------------------- | ----------------------------------------------------------------------- |
| `not_configured_for_verification` | This instance has no `publicKeys` registered.                           |
| `missing_signature_headers`       | One or more `X-Signature-*` headers absent.                             |
| `timestamp_invalid`               | `X-Signature-Timestamp` isn't a valid number.                           |
| `timestamp_out_of_window`         | Timestamp is outside `maxSkewMs` of server time — likely stale/delayed. |
| `replayed_nonce`                  | This nonce was already used — possible replay attack.                   |
| `unknown_key_id`                  | `X-Signature-KeyId` isn't in this instance's `publicKeys`.              |
| `signature_malformed`             | `X-Signature` isn't valid base64 or isn't 64 bytes decoded.             |
| `invalid_signature`               | Signature doesn't match the payload — tampering, wrong key, or bug.     |
| `verification_error`              | The underlying crypto call threw rather than returning a clean result.  |

`invalid_signature` specifically covers: tampered body, tampered params, tampered path/method, tampered timestamp/nonce, or a signature made with the wrong private key for the claimed `keyId`.

---

## Configuration API

| Property           | Type                           | Required For     | Description                                                                                                               |
| ------------------ | ------------------------------ | ---------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `mode`             | `"sign" \| "verify" \| "both"` | **All**          | Operational mode of the instance.                                                                                         |
| `keyId`            | `string`                       | `sign`, `both`   | Identifier for the key being used to sign requests.                                                                       |
| `privateKeyBase64` | `string`                       | `sign`, `both`   | The full 64-byte `@stablelib/ed25519` secret key (seed + public key), base64-encoded. Not a bare 32-byte seed.            |
| `publicKeys`       | `Record<string, string>`       | `verify`, `both` | Map of `keyId`s to 32-byte Ed25519 public keys, base64-encoded.                                                           |
| `maxSkewMs`        | `number`                       | Optional         | Max allowed difference (ms) between server time and request timestamp, and the nonce cache TTL. Defaults to 90,000 (90s). |
| `nonceStore`       | `NonceStore`                   | Optional         | Custom adapter for tracking nonces. Defaults to an `InMemoryNonceStore` — replace this in any multi-instance deployment.  |

---

## Security Best Practices

1. **Keep private keys secret.** Never expose `privateKeyBase64` in a client-side bundle unless it's a keypair intentionally scoped to a single authenticated user/device.
2. **Dispose of keys explicitly.** `APIGuard.init()` does not automatically wipe a previously-created instance's key material — if you're rotating keys or discarding an instance in a long-running process, call `guard.dispose()` on it yourself.
3. **Use a distributed nonce store outside single-instance deployments.** The default in-memory store only prevents replay within the same process/isolate.
4. **Use HTTPS.** APIGuard protects against tampering and replay, not eavesdropping — TLS is still required to keep the payload itself confidential in transit.
5. **Capture raw request bodies on the server**, never re-serialized ones — see the [Express integration note](#using-nodejs-express--fastify).

---
## Contributing

If you want to contribute or help extend support to more platforms or file formats, reach out via email. All contributions are welcome!

---

## License

[Apache-2.0](LICENSE) — free for personal and commercial use.

---

## Author

Developed by **Josef Elijah Fabian (Zelijah)** | [Majikah Solutions OPC](https://majikah.solutions/about)

**Developer**: [Josef Elijah Fabian](https://github.com/jedlsf)

**GitHub**: [https://github.com/Majikah](https://github.com/Majikah)

**Project Repository**: [https://github.com/Majikah/api-guard](https://github.com/Majikah/api-guard)

---

## Contact

- **Business Email**: [business@majikah.solutions](mailto:business@majikah.solutions)
- **Official Website**: [https://www.thezelijah.world](https://www.thezelijah.world)
- **Majikah Ecosystem**: [https://majikah.solutions](https://majikah.solutions)