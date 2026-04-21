# Trust store

`trust_store.json` at the repo root lists Ed25519 public keys Intel trusts to sign incoming artifacts.

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
