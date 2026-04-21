# Trust store

`trust_store.json` at the repo root lists Ed25519 public keys Intel trusts to sign incoming artifacts.

Intel also **signs** its own published outputs (`intel_snapshot.json`, `block_candidates.json`) using two separate Ed25519 keypairs (see `keys/README.md`). Downstream consumers such as Sweeps_Relief add Intel’s **public** keys to their trust store to verify those artifacts; private keys stay only under `keys/` in this repo.

**Public keys only.** Private keys belong in each signing repo's `keys/` directory (which is gitignored), never here.

To add a new trusted key:

1. Obtain the `public.pem` from the signing repo (e.g. Scout's `keys/public.pem`)
2. Add a new object to the `keys` array following the SIGNING.md schema
3. Update `updated_at` to current UTC
4. Commit the change with message explaining the key's purpose

To revoke:

1. Set `revoked_at` to the UTC timestamp of revocation
2. Set `revocation_reason` to a short human-readable string
3. Do NOT delete the key entry — revocation is auditable, deletion isn't
