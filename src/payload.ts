// src/payload.ts
//
// Domain-separated, versioned signing payload — same convention as
// majik-signature: a fixed domain prefix + JSON metadata. This means:
//   - An APIGuard signature can never be confused with a signature from
//     a different protocol/scheme, even if it happens to sign the same
//     underlying bytes (domain separation).
//   - Optional fields are omitted entirely (not `null`) when absent, so
//     payloads without params stay byte-identical across client versions
//     — same backward-compat trick as majik-signature's `alh`/`vu` fields.

const APIGUARD_SIGNATURE_VERSION = 1;
const APIGUARD_SIGNATURE_DOMAIN = "apiguard-sig-v1:";

export interface PayloadFields {
  keyId: string;
  timestamp: number;
  nonce: string;
  method: string;
  path: string;
  bodyHash: string;
  /** Hex hash of the canonicalized query params. Omit entirely (not "")
   *  when there are no params, to keep payloads byte-identical to
   *  requests that never had params. */
  paramsHash?: string;
}

export function buildSigningPayload(fields: PayloadFields): Uint8Array {
  const meta = JSON.stringify({
    v: APIGUARD_SIGNATURE_VERSION,
    id: fields.keyId,
    ts: fields.timestamp,
    n: fields.nonce,
    m: fields.method.toUpperCase(),
    p: fields.path,
    bh: fields.bodyHash,
    ...(fields.paramsHash !== undefined ? { ph: fields.paramsHash } : {}),
  });
  const prefix = new TextEncoder().encode(APIGUARD_SIGNATURE_DOMAIN);
  const body = new TextEncoder().encode(meta);
  const out = new Uint8Array(prefix.length + body.length);
  out.set(prefix, 0);
  out.set(body, prefix.length);
  return out;
}

/** Canonical, order-independent query-string encoding for GET-style params.
 *  Returns undefined (not "") when there are no params, so callers can
 *  omit `paramsHash` entirely rather than hashing an empty string. */
export function canonicalizeParams(
  params?: Record<string, string | number | boolean | null | undefined>,
): string | undefined {
  if (!params || Object.keys(params).length === 0) return undefined;
  const keys = Object.keys(params).sort();
  return keys
    .filter((k) => params[k] !== undefined)
    .map((k) => `${k}=${String(params[k])}`)
    .join("&");
}
