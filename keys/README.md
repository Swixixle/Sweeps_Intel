Ed25519 keys for signing Intel outputs.

Two keypairs, one per artifact type:

- snapshot keypair: signs `data/published/intel_snapshot.json`
- blocklist keypair: signs `data/published/block_candidates.json`

Generate:

```bash
python -m intel.exporters --generate-keypair-snapshot ./keys/snapshot
python -m intel.exporters --generate-keypair-blocklist ./keys/blocklist
```

- `private.pem` in each subdir: NEVER commit, NEVER share, NEVER paste into chat.
- `public.pem`: safe to share; paste into Relief's `trust_store.json` to enable verification.

Permissions on `private.pem` should be `0600` (set automatically by `--generate-keypair-*` on POSIX).
