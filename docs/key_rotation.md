# Key rotation

Intel signs `intel_snapshot.json` and `block_candidates.json` with two separate private keypairs (stored in `keys/snapshot/` and `keys/blocklist/`). The corresponding public keys must be listed in Sweeps_Relief's trust store. Rotation is manual today; automation is a future concern (see `docs/KEY_DISTRIBUTION.md` for the spec).

Two keypairs means rotation can happen independently — the snapshot key and blocklist key don't rotate together unless you want them to. This section documents rotating either one.

## When to rotate

- **Suspected compromise.** Any reason to believe a private key leaked: machine compromise, accidental commit, unexpected copy. Rotate immediately.
- **Scheduled rotation.** Good practice annually even without incident. Put it on a calendar.
- **Personnel change.** If the operator who generated the keys hands off the project.

## Rotation procedure (snapshot key example — same pattern for blocklist)

1. **Generate the new keypair** to a new directory:
   ```bash
   python -m intel.exporters --generate-keypair-snapshot ./keys/snapshot-new
   ```

   Don't overwrite `keys/snapshot/` until the new key is confirmed working end-to-end.

2. **Produce the trust-store entry** for Sweeps_Relief:
   ```bash
   python scripts/trust_store_entry.py \
     --pem keys/snapshot-new/public.pem \
     --key-id intel-snapshot-key-v2 \
     --authorized-for intel_snapshot
   ```

   Copy stdout into Sweeps_Relief's `trust_store.json` as a new entry in `keys[]`. Do NOT delete the `-v1` entry yet.

3. **Commit the trust store update in Relief:**
   ```bash
   cd ~/Sweeps_Relief
   # Edit trust_store.json, paste the new entry
   git add trust_store.json
   git commit -m "trust: add intel-snapshot-key-v2 during rotation"
   git push
   ```

4. **Switch Intel to the new key:**
   ```bash
   cd ~/Sweeps_Intel
   python -m intel.exporters \
     --sign-snapshot \
     --snapshot-private-key keys/snapshot-new/private.pem \
     --snapshot-key-id intel-snapshot-key-v2 \
     [existing flags]
   ```

   Verify that signed output validates in Relief before proceeding.

5. **Revoke the old key** after a grace period (minimum 30 days). Edit Relief's trust_store.json:
   ```json
   {
     "key_id": "intel-snapshot-key-v1",
     "revoked_at": "2026-05-21T00:00:00Z",
     "revocation_reason": "scheduled rotation to v2"
   }
   ```

   Commit this separately from the key addition.

6. **Move the new key into place:**
   ```bash
   mv keys/snapshot keys/snapshot-archived-v1
   mv keys/snapshot-new keys/snapshot
   ```

   Keep archived keys for forensic verification of old signed artifacts.

## Rotating the blocklist key

Same procedure as above, substituting:
- `--generate-keypair-blocklist` for `--generate-keypair-snapshot`
- `keys/blocklist/` paths for `keys/snapshot/`
- `intel-blocklist-key-v*` for the key_id
- `--authorized-for intel_block_candidates` in the helper call
- `--sign-blocklist` and `--blocklist-private-key` for the signing flags

Rotating both at the same time is supported but uncommon — do them as separate transitions unless there's a reason to couple them.

## What NOT to do

- **Do not rotate both keys simultaneously** unless you have a specific reason. Independent rotation limits blast radius of a botched rotation.
- **Do not delete old key entries from Relief's trust store.** Revocation preserves audit history.
- **Do not reuse a `key_id`** across different keypairs. Increment the version suffix.
- **Do not commit private keys.** Double-check `git status` during multi-directory rotation.
- **Do not skip the grace period.** Revoking before Relief has the new key breaks Relief's ability to verify Intel's output mid-rotation.
