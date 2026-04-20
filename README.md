# Sweeps_Intel

## What Intel is

Sweeps_Intel is the **curation-side** component of a three-repo sweepstakes casino accountability pipeline. It ingests candidate domains and fingerprints from [Sweeps_Scout](https://github.com/Swixixle/Sweeps_Scout), clusters sibling brands using shared infrastructure signals (including TLS/DNS/MX fingerprints when provided), and supports promoting **human-reviewed** entities into normalized JSON and published bundles consumed by [Sweeps_Relief](https://github.com/Swixixle/Sweeps_Relief). It is **stdlib-only at runtime**, local-first, and written for deterministic, reviewable outputs.

Nothing in this repo calls Relief directly; the contract is **files on disk** (normalized + published JSON).

## Pipeline position

```mermaid
flowchart LR
  Scout[Sweeps_Scout]
  Intel[Sweeps_Intel]
  Relief[Sweeps_Relief]
  Scout -->|file handoff| Intel
  Intel -->|published / block candidates| Relief
```

Inside Intel, the rough shape is:

**ingest → stage → review → (optional) promote → publish**

- **Review gate:** automated rules (`review_rules.py`) and human judgment over JSON artifacts (`review_queue.json`, `review_decisions.json`, staged clusters, Scout promotion summary). **No path writes production seeds or published outputs without you choosing to run those steps after review.**

## Data model

| Layer | What it is |
|--------|------------|
| **Production entities** | Dataclasses in `src/intel/schemas.py`, serialized to `data/normalized/entities.json`. IDs are **string slugs** from seeds (e.g. `operator_chumba`). |
| **Entity types** | `operator`, `promoter`, `provider`, `payment_path` (literal on `Entity`). |
| **Candidates** | Scout and research intake live under `data/research_candidates/` (staged JSON, clusters, extracted fingerprints, etc.) before any promotion to `data/seeds/`. |
| **Relationships** | Separate edge list in `relationships.json`: `from_id`, `to_id`, free-form `relationship` string, `confidence`, `source`, optional evidence. Not a closed enum. |
| **Scout fingerprints** | `src/intel/scout_fingerprint_loader.py` reads `domain_fingerprints.json` and emits pairwise signals. `src/intel/cluster.py` **auto-merges** only **reciprocal TLS SAN** pairs (definitive). Other signals (one-way SAN, filtered shared NS/MX) feed **`build_affiliations_from_scout_fingerprints()`** in `affiliations.py`—domain-level `Affiliation` rows for review workflows—not the main `run_affiliations()` CLI, which scores **seed entity IDs** from normalized JSON. |
| **Infrastructure noise** | `src/intel/infra_denylist.py`: suffix/prefix rules so shared Cloudflare-style NS/MX do not dominate clustering. |

## Status

| Area | Status |
|------|--------|
| Normalize (seeds → JSON) | Implemented (`intel.normalize`) |
| Clustering (union-find + evidence) | Implemented (`intel.cluster`); Scout reciprocal TLS wired |
| Affiliations (entity pairs from seeds) | Implemented (`intel.affiliations` → `run_affiliations`) |
| Scout fingerprint → domain affiliations | Implemented (`build_affiliations_from_scout_fingerprints`; script/REPL, no dedicated CLI yet) |
| Review rules + decisions | Implemented (`intel.review_rules`, `intel.review_queue`) |
| Scout CSV import + promotion summary | Implemented (`intel.import_scout_candidates`, `intel.review_scout_candidates`) |
| Export (snapshots + block candidates) | Implemented (`intel.exporters`) |
| Cryptographic signing of published artifacts | **Not implemented** (planned; Relief may sign downstream—Intel outputs here are unsigned today) |

## Install

Requires **Python 3.11+** (see `pyproject.toml`). Runtime **dependencies = []** by design; dev uses pytest only.

```bash
git clone https://github.com/Swixixle/Sweeps_Intel.git
cd Sweeps_Intel
python3 -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
python3 -m pytest tests/ -q
```

## Running the pipeline (common commands)

From repo root with `PYTHONPATH=src` or after `pip install -e ".[dev]"`:

| Command | Role |
|---------|------|
| `python -m intel.normalize` | Seeds CSVs → `data/normalized/{entities,fingerprints,relationships}.json` |
| `python -m intel.affiliations` | Normalized entities → pairwise `affiliations.json` (slug IDs, seed fingerprints) |
| `python -m intel.cluster` | Clustering (includes Scout `domain_fingerprints.json` reciprocal TLS links when present) |
| `python -m intel.review_queue` | Build prioritized `review_queue.json` |
| `python -m intel.review_rules` | Emit `review_decisions.json` from staged + normalized context |
| `python -m intel.exporters` | `data/published/intel_snapshot.json` + `block_candidates.json` |
| `python -m intel.import_scout_candidates` | Scout CSVs → `data/research_candidates/staged_from_scout/` |
| `python -m intel.review_scout_candidates` | Summarize Scout staging for promotion review |

Other modules with CLIs: `intel.enrich`, `intel.extract`, `intel.discover`, `intel.monitor`, `intel.stage_research_import`, `intel.promote_research_candidates`, `intel.export_reviewed_blocklist`—use `--help` on each.

## Scout handoff

There is **no network** between Scout and Intel. The contract is **copy files** into this repo (or a shared volume).

- Place **`domain_fingerprints.json`** under `data/research_candidates/scout_import/` for TLS/DNS/MX clustering and affiliation helpers.
- Scout **candidate CSVs** (operators, promoters, corporate, redirects) go in the same directory for `import_scout_candidates`.
- If you use **`discovered_domains.json`** from Scout, align with your ops layout: `intel.cluster` also reads `data/candidates/discovered_domains.json` for redirect-chain linking when that file exists locally.

## Trust and review gates (Option C)

- **Definitive:** reciprocal cert SAN cross-reference (after infra filtering) → **auto-merge** in `cluster.py`.
- **Strong hints:** one-way SAN, shared non-noise NS/MX → **affiliation-style evidence** via `build_affiliations_from_scout_fingerprints()` (review, not automatic production merge).
- **Noise:** CDN/default MX/NS patterns → filtered in `infra_denylist.py` (curated list; wrong entries can hide real signal—edit deliberately).
- **Promotion:** production slugs and seeds change only when you run normalize/promote/export after review—not silently from clustering alone.

**Signing:** Intel does not yet sign `intel_snapshot.json` / `block_candidates.json`; treat that as a planned hardening step.

## Architecture pointers

| Repo | Role |
|------|------|
| [Sweeps_Scout](https://github.com/Swixixle/Sweeps_Scout) | Discovery and fingerprint **collection**; emits handoff files. |
| **Sweeps_Intel** (this repo) | **Curation**: normalize, cluster, review, publish bundles. |
| [Sweeps_Relief](https://github.com/Swixixle/Sweeps_Relief) | Enforcement surface; consumes published intel (e.g. blocklist). |

## Development notes

- **Zero runtime deps**—prefer stdlib; keep JSON **sorted keys** where writers already do so for diffable outputs.
- **Narrow exception handling** in hot paths; log warnings for expected bad inputs.
- **Small, intentional commits**; do not commit `data/` research outputs that are gitignored—check `git status` before push.

## Limitations

- Scout fingerprint signals are only as good as Scout’s crawl coverage and the copied `domain_fingerprints.json`.
- The infra denylist is **manual**; a false positive there can hide real operator correlation—fix in `src/intel/infra_denylist.py`.
- Review UX is **JSON on disk** (queue, decisions, clusters)—no web UI in this repo.
- **Signed exports** are not implemented here yet.
- **ID spaces differ**: candidates (`scout_*`, `research_*`, domains in clusters) vs production **slug IDs**—promotion must map explicitly.

## License

MIT — see [LICENSE](LICENSE).
