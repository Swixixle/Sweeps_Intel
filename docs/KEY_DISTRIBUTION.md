# Key distribution specification

> **Location note:** This spec currently lives in Sweeps_Intel/docs/ because SIGNING.md lives here. When the Nikodemus project family grows or this spec stabilizes, both documents should extract to a dedicated specs repository. Any implementation of this spec should reference it by commit SHA to survive that move. Consumers referencing `docs/KEY_DISTRIBUTION.md` by path only will break when extraction happens.

> **Relationship to SIGNING.md:** This spec details and supersedes the "future root-signed manifests" bullet in SIGNING.md § Known limitations. Where the two documents overlap, this one wins on trust-store and distribution questions; SIGNING.md wins on artifact envelope format.

## Purpose

This document specifies how Ed25519 signing keys are distributed, rotated, revoked, and trusted across the Nikodemus project family. It complements `SIGNING.md` (which defines the envelope format for individual signed artifacts) by defining the meta-layer: how verifiers decide which keys to trust in the first place.

**Current state (2026-04-21):** manual — operators copy public keys between repos' `trust_store.json` files using a helper script (`scripts/trust_store_entry.py`). This works for single-operator deployments and is the baseline until one of the triggers in § "When to implement" fires.

**Intended end state:** signed key manifests, fetched through a verifiable channel, such that a new Relief install or a new journalist running an investigation tool can bootstrap trust without manual JSON edits.

## Scope

This spec applies to every project in the Nikodemus family that produces or consumes signed artifacts. Current and anticipated members:

- **Sweeps_Scout** — signs `domain_fingerprints.json`
- **Sweeps_Intel** — verifies Scout; signs `intel_snapshot.json`, `block_candidates.json`
- **Sweeps_Relief** — verifies Intel; internally signs `policy.json`, log bundles (distinct format, migration tracked separately)
- **Open Case** — signs investigation receipts, pattern-engine rule outputs
- **EthicalAlt** — signs profile-corroboration receipts, research dossiers
- **Debrief** — signs repo analysis reports
- **Frame** — signs journalist dossier cards, author resolution attestations
- **testimony-corpus** — signs consent records, contribution receipts (strict additional rules per ETHICS.md)

Projects in this family share infrastructure and principles but do not share implementation — each repo implements signing and verification per `SIGNING.md` using whatever canonicalization and storage fits the project's audience.

**testimony-corpus exclusion.** testimony-corpus is explicitly out of scope for Decision 3 (external contributor attestations). Consent records and contribution receipts in that project are authored by the contributor and cannot be re-attested by outside parties without breaking the consent model. testimony-corpus may use other reserved fields in the v2 schema for its own purposes, but the contributor-tier signing mechanism is incompatible with its ethical posture.

## Design decisions to make

Three questions this spec intentionally leaves open for the author to decide after reading:

### Decision 1: Root of trust scope

What does *one* root key sign for?

| Option | Blast radius of root compromise | Operational burden | Fits for |
|---|---|---|---|
| **A. Single root for all Nikodemus projects** | Catastrophic — every signed artifact in every project becomes untrusted | Lowest — one root key, one rotation ceremony | Projects that genuinely share trust semantics |
| **B. Per-project-family roots** (Sweeps root, Open Case root, EthicalAlt root, testimony-corpus root, etc.) | Bounded — compromise of Sweeps root does not affect Open Case | Moderate — ~5-7 root keys across projects | Projects that share audience but have different risk profiles |
| **C. Per-repo roots** (every repo has its own root, no hierarchy) | Tiny per incident | Highest — every downstream verifier must track every upstream repo's root | Projects that are genuinely independent and have no cross-project trust relationships |

**Analysis:**

Option A is tempting because it's simple. It is also the most dangerous. The root key becomes a single point of catastrophic failure. If it's on one machine, that machine becomes the most sensitive system in the entire project family. If it's on multiple machines, you've created synchronization and audit problems around the most important secret you have.

Option C is the safest per-incident but turns into operational chaos at scale. If testimony-corpus needs to verify an Open Case investigation receipt, and Open Case needs to verify an EthicalAlt corroboration, you're now maintaining a mesh of N² trust relationships.

Option B is the middle ground and matches how real-world trust families work. The Sweeps trio genuinely shares trust (Scout → Intel → Relief is one pipeline). Open Case and EthicalAlt genuinely share trust (both are civic-accountability projects with overlapping audiences). testimony-corpus deserves its own root because its ethical posture is strict enough that conflating its trust with investigation tooling is a category error.

**Recommended default for this spec: Option B, per-project-family roots.** Author overrides possible; if overriding, update this section with reasoning and date.

**Author decision: Deferred — revisit when a "When to implement" trigger fires.**

### Decision 2: Distribution channel

How do operators' trust stores learn about new keys and revocations?

| Option | Trust anchor | Freshness guarantee | Offline-friendly | Complexity |
|---|---|---|---|---|
| **A. Git-based, manual pull** | The repo URL (TLS-terminated clone) | Whenever the operator runs `git pull` | Yes, once cloned | Lowest |
| **B. HTTPS-fetched signed manifest** | Root key + TLS | Configurable polling interval | No, requires network on refresh | Moderate |
| **C. Both — HTTPS happy path, git fallback** | Both | Best of both | Yes for fallback | Highest |
| **D. Sigstore / transparency log** | External third party (e.g. Rekor) | Append-only log | Depends on log | High; introduces external dependency |

**Analysis:**

Git-based distribution (Option A) provides an attributable audit trail — stronger still if commits or tags are GPG-signed per git's standard mechanisms. A committed, pushed trust-store update has public history that outside parties can independently inspect. Journalists running Relief can verify that a new key in their local `trust_store.json` corresponds to a specific commit in a public repo, made by a specific author, at a specific time. That's real provenance, even without additional signing.

HTTPS-fetched manifests (Option B) are the pattern used by most real-world key distribution (Sigstore, package manager signing, CT logs). They handle the "we need to revoke this NOW" case better than git, because you're not waiting for operators to `git pull`. They also work for non-technical operators who don't have git workflows.

Option C combines both but adds complexity — you need to decide which wins in case of conflict, how to handle partial failures, etc.

Option D outsources trust to an external party (Sigstore's Rekor is the obvious candidate). Strong security properties, but you've made your trust depend on a third party's continued existence and good behavior.

**Recommended default: Start with Option A (git-based) at implementation time.** Migrate to Option C when revocation latency becomes a real concern — i.e., when there's a real non-hypothetical key compromise and the rotation takes too long. Defer D unless you decide you actively want the transparency-log property.

**Author decision: Option A (git-based). Migrate toward C when any "When to implement" trigger fires. Decided 2026-04-21.**

### Decision 3: External signed attestations

Should verifiers accept signatures from parties outside the Nikodemus family?

The question matters because if Open Case wants to let an outside journalist cryptographically attest "I verified this finding matches primary sources," that attestation is a signature, by a key, that Open Case's verifier needs to trust.

| Option | Tradeoff |
|---|---|
| **A. No — only Nikodemus-family keys sign things** | Simpler trust model, smaller attack surface, but loses a real use case |
| **B. Yes, via a separate "contributor" trust tier** | More complex model; contributor keys cannot sign production artifacts but can sign attestations about them |
| **C. Deferred — design now, implement later** | Don't close the door, but don't build yet |

**Recommended default: Option C.** Reserve space in the schema for a `role` or `trust_tier` field on TrustedKey entries so that adding external contributor keys later is an additive change, not a breaking one. Don't implement the contributor path until there's a real contributor to test it with.

**Author decision: Deferred — revisit when a "When to implement" trigger fires.**

## Schema additions for future-compatibility

These additions are reserved in the schema now, even though nothing uses them yet, so that later work is additive:

```json
{
  "schema_version": 2,
  "updated_at": "ISO-8601 UTC",
  "root_key_id": "nikodemus-sweeps-root-v1",
  "root_signature_b64": "base64url signature over canonical keys[] array (future)",
  "keys": [
    {
      "key_id": "scout-fingerprint-key-v1",
      "algorithm": "ed25519",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
      "issued_at": "2026-04-21T00:00:00Z",
      "authorized_for": ["domain_fingerprints"],
      "trust_tier": "production",
      "issuer_key_id": "nikodemus-sweeps-root-v1",
      "issuer_signature_b64": "base64url signature over canonical entry (future)",
      "revoked_at": null,
      "revocation_reason": null,
      "expires_at": null
    }
  ]
}
```

New fields vs current schema (v1):
- `root_key_id`: which root signed this manifest
- `root_signature_b64`: signature over the canonical `keys` array
- `trust_tier`: one of `"production"`, `"contributor"`, `"test"` (reserved for Decision 3 future work)
- `issuer_key_id`: which root signed this specific key entry
- `issuer_signature_b64`: the root's signature over this entry's canonical form
- `expires_at`: optional auto-revocation timestamp

Current implementations (schema_version 1) ignore unknown fields, so adding these to trust_store.json now does not break anything.

## Key lifecycle

### Issuance

When a project generates a new keypair:

1. Generate Ed25519 keypair locally. Private key stays on the generating machine, permissions 0600, never committed.
2. Public key is written to `keys/public.pem` (or `keys/<purpose>/public.pem` for projects with multiple key purposes).
3. Operator runs `scripts/trust_store_entry.py` to produce the trust-store JSON block.
4. Operator signs the trust-store update with the appropriate root key (future, when Decision 1 resolves and root keys exist).
5. The update is committed to each downstream verifier's repo and pushed.

### Rotation

Rotation is a planned transition from key v_N to key v_(N+1). Both keys must be trusted simultaneously during a grace period so in-flight signed artifacts remain verifiable.

Procedure:
1. Generate v_(N+1) keypair.
2. Add v_(N+1) entry to downstream trust stores, committed and pushed. v_N entry is unchanged.
3. Switch signing workflow to use v_(N+1).
4. After grace period (minimum 30 days, longer if old signed artifacts are in circulation), revoke v_N by setting `revoked_at` and `revocation_reason`.
5. v_N entry is retained in the trust store indefinitely with revocation metadata — this is the audit trail.

### Revocation

Revocation is an unplanned transition triggered by compromise or suspected compromise.

Procedure:
1. Set `revoked_at` and `revocation_reason` on the compromised key in every downstream trust store. Commit and push immediately.
2. Audit all signed artifacts produced with the compromised key. Artifacts signed before the suspected compromise timestamp may be retrospectively trusted; artifacts after cannot. Decision is per-case and documented.
3. Generate a replacement key (treated as a rotation, but without the grace period).
4. If the root key itself is compromised, revocation becomes a re-root ceremony: new root key, new trust-store signature over every downstream key, announce through every available channel. This is the worst case and should be rehearsed before it happens.

### Expiration

`expires_at` is reserved for future automated rotation. A key with a non-null `expires_at` becomes untrusted after that timestamp regardless of `revoked_at`. Not yet implemented in verifiers; safe to ignore in v1.

## When to implement

Deliberate triggers for migrating from manual (current) to signed-manifest distribution:

1. **Multiple operators.** More than one person or machine runs a verifier (journalist installs Relief on their laptop, for example). Manual distribution across N machines is an error-prone O(N) task.
2. **Revocation latency matters.** A real key compromise has happened and the manual "edit trust_store.json in every repo and push" process took too long.
3. **Artifact consumers outside the project.** An external journalist wants to verify an Open Case finding programmatically, without cloning Open Case's repo. They need a fetchable manifest.
4. **Cross-project trust.** Two project families need to verify each other's artifacts (e.g., testimony-corpus contributions cite Open Case investigations by receipt ID). Manual bilateral trust store copying across project families becomes untenable.

None of these are currently true. Implementing before one is true is premature.

## Implementation blueprint

When the time comes, this is the rough shape of the implementation, broken into phases that deliver value incrementally.

### Phase 0: Root key generation (few hours)

- Decide Decision 1 scope (single, family, per-repo).
- Generate root keypair(s) on a dedicated signing machine or hardware token. Private key never leaves that environment.
- Document the ceremony: who generated it, when, where, what was witnessed.
- Back up private key to offline storage (hardware token, encrypted USB in a safe, paper backup of seed material — whatever matches the threat model).
- Publish public root key(s) through the channel of choice (git-committed, HTTPS-served, both).

### Phase 1: Schema upgrade (~1 day)

- Update `SIGNING.md` trust-store schema from v1 to v2 with the additive fields above.
- Update every verifier to parse v2 while remaining backward-compatible with v1.
- Migrate existing trust stores to v2 format (mechanical change, fill in `root_key_id` etc.).
- Note: `schema_version` remains an integer in v2 (the current Intel loader parses it as int). If a future revision introduces string or SemVer versioning, that is a separate, intentional loader change, not a property of v2.

### Phase 2: Signed manifest generation (~2 days)

- Build a tool (call it `nikodemus-sign-manifest` or similar) that:
  - Reads a candidate trust store
  - Canonicalizes the `keys[]` array
  - Signs the canonical form with the root private key
  - Writes `root_signature_b64` into the manifest
- Tool lives in a dedicated location, not per-repo. Private key is only accessible to this tool's execution context.
- Manual operators continue using `trust_store_entry.py` to *propose* entries, then the signing tool produces the signed manifest.

### Phase 3: Verifier updates (~1 day per project family)

- Every verifier gains a root-signature verification step before trusting any key in the trust store.
- Verification is cached (don't re-verify the whole manifest on every artifact verification — do it once per trust-store-load).
- Falling back to unsigned trust stores is configurable during transition, default off in production.

### Phase 4: Distribution mechanism (~2-5 days depending on Decision 2)

- If Option A (git-based): write a `git_trust_store_fetcher.py` that pulls a specific repo, verifies the latest commit, extracts trust_store.json. Mostly glue code.
- If Option B (HTTPS): host the signed manifest at a stable URL. Verifiers fetch, verify root signature, update local trust store. Caching, staleness checks, fallback behavior all become real design questions.
- If Option C (both): implement B as primary, A as fallback. Roughly B + A - some overlap.

### Phase 5: Rotation automation (~1-2 days)

- CLI tool for the rotation ceremony: generate new key, update trust store, sign manifest, publish, after grace period flip revocation, publish again.
- Not strictly required but saves the operator from multi-step manual procedures where a mistake is expensive.

### Phase 6: Contributor tier (deferred, open-ended)

- Implement trust_tier distinction in verifiers. Production-tier keys can sign any artifact; contributor-tier keys can sign only attestations (a new artifact_type).
- Design attestation envelope format (separate from SIGNING.md, specific to "I, contributor X, vouch for artifact Y").
- Process for accepting contributor keys into the manifest. Requires human review.

## Rough total effort when built

**Indicative only.** These numbers are order-of-magnitude planning guesses for a solo operator working in focused sessions. They exist to prevent someone from underestimating the work, not to drive sprint planning or funding conversations. Delete this block if it becomes a hostage to fortune.

Phase 0-4 with Option A (git-based, per-family roots, no contributor tier): approximately **5-8 working days** of focused engineering. Longer calendar time expected given the review discipline this project applies to everything.

Phase 0-4 with Option C (HTTPS+git, per-family roots): approximately **8-12 working days**.

Full implementation including contributor tier and automation: **15-25 working days**.

These are lower bounds assuming the operator has the uninterrupted time. Realistic calendar time is probably 2-4x depending on other commitments.

## What the implementation is NOT allowed to do

Hard constraints preserved from the ethical posture of the projects this serves:

- **Offline verification must always work given a trust store and the artifact on local disk.** Distribution mechanisms may use HTTPS, mirrors, or external services — but once an operator has the trust store and the signed artifact, verification must never require a live network or third-party availability. A journalist in a contested network environment, on a plane, or working from an offline machine must be able to verify what they have.
- **The system must not create a central authority that can be compelled to change or withhold trust information without operator consent.** This is a design principle, not a guarantee against legal process against the individual humans who hold keys — see Open Questions § Key escrow for the real limitations of that position.
- **Must not conflate signing identity with contributor identity.** A signing key identifies a key, not a person. Audit trails about "who signed this" require a separate accountability layer outside the crypto stack.

## Open questions beyond this spec

- **Cross-signing with other civic-tech projects.** If ProPublica or The Markup adopt compatible signing, is there a story for mutual trust? Deferred; won't matter until the projects reach that audience.
- **Hardware security modules.** Does the root key live on a YubiKey, a smartcard, an offline machine, in a safe? Depends on threat model. Deferred to implementation time.
- **Key escrow.** If the operator is incapacitated, can someone else access the root key? Addressing this too early creates more risk (someone else has the key); addressing it too late creates single-operator bus factor risk. Depends on the project's real operational continuity plan, which does not exist today.

## Revision history

- **2026-04-21** — Initial draft. Decision 2 resolved (Option A, git-based); Decisions 1 and 3 deferred. Status: design reference, not yet implemented. Spec lives in Sweeps_Intel/docs/ pending extraction to a dedicated specs repository.
