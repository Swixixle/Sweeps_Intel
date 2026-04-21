# Signing envelope format

This document defines the signed artifact envelope used across Sweeps_Scout, Sweeps_Intel, and Sweeps_Relief. Any signed JSON artifact produced by any of the three repos MUST conform to this format. Verifiers MUST reject artifacts that deviate.

## Envelope shape

```json
{
  "payload": { ...arbitrary signed content... },
  "signature": {
    "algorithm": "ed25519",
    "key_id": "scout-fingerprint-key-v1",
    "signed_at": "2026-04-21T14:22:00Z",
    "payload_hash_sha256": "hex-encoded sha256 of canonical payload",
    "signature_b64": "base64url-encoded signature bytes"
  }
}
```

## Canonicalization

The payload is hashed after canonical JSON serialization:

- `json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`
- Encoded as UTF-8 bytes
- SHA-256 digest, hex-encoded

**What gets signed.** The signature is computed over the **canonical_payload bytes directly** — Ed25519 performs its own hashing internally. The `payload_hash_sha256` field in the envelope is an **informational integrity aid**: it lets a human reading the file verify the payload matches what the signer thought they were signing, without needing to run Ed25519 verification. Verifiers SHOULD check `payload_hash_sha256` matches as a sanity check (step 7), but the cryptographic trust decision is made in step 9 against the canonical payload, not against the hash field.

## Key IDs

Key IDs follow the pattern `{repo}-{purpose}-{version}`:

- `scout-fingerprint-key-v1` — signs Scout's `domain_fingerprints.json` outputs
- `intel-snapshot-key-v1` — signs Intel's published snapshots
- `intel-blocklist-key-v1` — signs Intel's block candidates
- `relief-log-key-v1` — signs Relief's event log bundles

Version numbers increment on key rotation. Old versions remain in trust stores for verification of historical artifacts until explicit revocation.

## Trust store

Each repo that verifies signatures maintains a `trust_store.json` file listing trusted public keys:

```json
{
  "schema_version": 1,
  "updated_at": "2026-04-21T14:22:00Z",
  "keys": [
    {
      "key_id": "scout-fingerprint-key-v1",
      "algorithm": "ed25519",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
      "issued_at": "2026-04-21T00:00:00Z",
      "authorized_for": ["domain_fingerprints"],
      "revoked_at": null,
      "revocation_reason": null
    }
  ]
}
```

Verifiers MUST:

1. Reject if `key_id` is not in the trust store
2. Reject if the matching key has `revoked_at` set
3. Reject if the artifact's purpose is not in the key's `authorized_for` list
4. Verify the signature cryptographically

## Verification algorithm

```
1. Parse envelope; require "payload" and "signature" objects
2. Require signature.algorithm == "ed25519"
3. Look up signature.key_id in trust store; reject if not found or revoked
4. Verify artifact purpose (inferred or explicit) is in key's authorized_for
5. Compute canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
6. Compute expected_hash = sha256(canonical_payload).hexdigest()
7. Compare expected_hash to signature.payload_hash_sha256; reject if mismatch
8. Decode signature.signature_b64 from base64url
9. Verify signature bytes against canonical_payload (Ed25519 handles internal hashing per RFC 8032) using public key
10. If all checks pass, return the payload; otherwise raise SignatureVerificationError with specific reason
```

## Signing algorithm

```
1. Take the payload dict to sign
2. Compute canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
3. Compute payload_hash_sha256 = sha256(canonical_payload).hexdigest()
4. Sign canonical_payload using the Ed25519 private key (produces 64 bytes)
5. Encode signature as base64url
6. Assemble envelope:
   {
     "payload": <original payload dict>,
     "signature": {
       "algorithm": "ed25519",
       "key_id": "<signer's key id>",
       "signed_at": "<ISO 8601 UTC timestamp>",
       "payload_hash_sha256": <from step 3>,
       "signature_b64": <from step 5>
     }
   }
7. Serialize envelope as canonical JSON for storage
```

## Known limitations

- No revocation timestamps on signatures themselves — if a key is revoked, all artifacts signed with that key become untrusted retroactively, regardless of when they were signed. This is deliberate; relaxing it requires adding a signed revocation log, which is out of scope for v1.
- No key delegation or hierarchy. Each key is independent. Root-signed trust-store manifests are a future hardening step.
- Trust store is edited manually; no automated distribution. Copy between repos by hand or via a sync script.
