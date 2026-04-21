# End-to-end signing chain test

This document describes the cross-repo integration test that verifies the full signing chain works with real keys: Scout signs, Intel verifies + signs, Relief verifies.

## What it tests

The chain is:

```
Scout                Intel                         Relief
-----                -----                         ------
sign fingerprints →  verify + ingest → sign     →  verify snapshot
                      snapshot + blocklist          verify blocklist
```

Every hop has a signature check. The test proves:

1. Scout's Ed25519 signing over canonical JSON produces envelopes that Intel's verifier accepts
2. Intel's own Ed25519 signing over canonical JSON produces envelopes that Relief's verifier accepts
3. Canonical JSON implementations across all three repos produce byte-identical output for the same input (silent mismatch would cause all signatures to fail this test)
4. Trust stores are correctly wired (Intel trusts Scout's key, Relief trusts Intel's two keys)

## Running it

### Prerequisites

All three repos cloned, venvs activated at least once to install packages:

```bash
for repo in ~/Sweeps_Scout ~/Sweeps_Intel ~/Sweeps_Relief; do
  cd "$repo"
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -e ".[dev]"
  deactivate
done
```

Keys generated in each repo that signs:

```bash
cd ~/Sweeps_Scout && source .venv/bin/activate
python -m sweep_scout.fingerprint --generate-keypair ./keys
deactivate

cd ~/Sweeps_Intel && source .venv/bin/activate
python -m intel.exporters --generate-keypair-snapshot ./keys/snapshot
python -m intel.exporters --generate-keypair-blocklist ./keys/blocklist
deactivate
```

Trust stores must hold the real public keys:

- **Intel's `trust_store.json`** must contain `scout-fingerprint-key-v1` with Scout's real `keys/public.pem` content
- **Relief's `trust_store.json`** must contain `intel-snapshot-key-v1` and `intel-blocklist-key-v1` with Intel's real `keys/snapshot/public.pem` and `keys/blocklist/public.pem` content

Use `scripts/trust_store_entry.py` in each repo to produce correctly-formatted entries.

### Run

```bash
cd ~/Sweeps_Intel
bash scripts/test_signing_chain.sh
```

Expected output on success:

```
Step 1/6: Scout signs fingerprints ... ✓ (Ns)
Step 2/6: Handoff to Intel ... ✓
Step 3/6: Intel verifies Scout's signature ... ✓
Step 4/6: Intel signs snapshot and blocklist ... ✓ (Ns)
Step 5/6: Handoff to Relief ... ✓
Step 6/6: Relief verifies Intel's signatures ... ✓

✓ Signing chain verified end-to-end
  fingerprints: 2
  entities: N
  relationships: N
```

### Failure modes

Common failures and what they mean:

- **Step 3 fails with `HashMismatchError`:** Scout's canonical JSON differs from Intel's canonical JSON at the byte level. Check that both `_canonical.py` implementations match SIGNING.md spec exactly.
- **Step 3 or 6 fails with `UntrustedKeyError`:** The trust store doesn't contain the expected key. Check that `trust_store.json` has been updated with the real public key (not a placeholder).
- **Step 4 fails with `FileNotFoundError` on private key:** Intel's `--generate-keypair-*` commands haven't been run. See prerequisites above.
- **Step 6 fails with `SignatureVerificationError: Ed25519 verification failed`:** Either the public key in Relief's trust store doesn't match Intel's private key, or canonical JSON drift between Intel and Relief. Relief uses `ensure_ascii=True` per spec — any drift to `ensure_ascii=False` in Relief's envelope code would cause this.

## When to run it

- After any change to any of the three repos' signing code (`_signing.py`, `_canonical.py`, envelope module)
- After any change to SIGNING.md or KEY_DISTRIBUTION.md
- Before releasing or tagging a version
- After a key rotation, to confirm the new keys work end-to-end before revoking old ones

## What this does NOT test

- Revocation: the test uses active, non-revoked keys only
- Multiple keys of same key_id (rotation grace period): test uses single key per role
- Network-based distribution (Decision 2 Option B): test uses filesystem-local trust stores
- Contributor tier (Decision 3): out of scope
- Relief's internal signing (policy.json, log bundles) — that's a separate envelope format, covered by Relief's own unit tests
