from __future__ import annotations

import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from intel.promote_research_candidates import run_promote
from intel.stage_research_import import classify_evidence_tier, run_stage


class TestEvidenceTier(unittest.TestCase):
    def test_inferred_wins_when_403_mentioned(self) -> None:
        self.assertEqual(
            classify_evidence_tier("Official terms also 403 on fetch", "https://x.com/terms"),
            "inferred_or_unverified",
        )

    def test_first_party_when_clean(self) -> None:
        self.assertEqual(
            classify_evidence_tier("quoted verbatim from official terms", ""),
            "first_party_verified",
        )

    def test_secondary_marker(self) -> None:
        self.assertEqual(
            classify_evidence_tier("corroborated by third-party reporting only", ""),
            "secondary_corroborated",
        )


class TestStageImport(unittest.TestCase):
    def test_preserves_notes_and_sources(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rc = root / "research_candidates"
            rc.mkdir(parents=True)
            inp = rc / "claude_fingerprint_dump.csv"
            header = [
                "domain",
                "brand",
                "legal_entity",
                "parent_company",
                "jurisdiction",
                "company_number",
                "provider_mentions",
                "cashier_path",
                "script_domains",
                "support_widget",
                "title_phrase",
                "footer_phrase",
                "analytics_ids",
                "contact_email",
                "mailing_address",
                "notes",
                "sources",
            ]
            row = [
                "a.example",
                "A Brand",
                "",
                "VGW Holding",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "verbatim from official site; no guesswork",
                "https://a.example/terms",
            ]
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(header)
            w.writerow(row)
            inp.write_text(buf.getvalue(), encoding="utf-8")
            run_stage(inp, rc, None)
            data = json.loads((rc / "staged_entities.json").read_text(encoding="utf-8"))
            ent = data["entities"][0]
            self.assertIn("verbatim", ent["notes"])
            self.assertIn("a.example/terms", ent["sources"])

    def test_does_not_write_production_seeds(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            seeds = root / "data" / "seeds"
            seeds.mkdir(parents=True)
            prod = seeds / "operators.csv"
            prod.write_text("id,name\nx,x\n", encoding="utf-8")
            before = prod.read_text()
            rc = root / "data" / "research_candidates"
            rc.mkdir(parents=True)
            inp = rc / "in.csv"
            inp.write_text(
                "domain,brand,legal_entity,parent_company,jurisdiction,company_number,"
                "provider_mentions,cashier_path,script_domains,support_widget,title_phrase,"
                "footer_phrase,analytics_ids,contact_email,mailing_address,notes,sources\n"
                "z.example,Z,,,,,,,,,,,,,,,note,src\n",
                encoding="utf-8",
            )
            run_stage(inp, rc, None)
            self.assertEqual(prod.read_text(), before)

    def test_cluster_relationships(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rc = root / "research_candidates"
            rc.mkdir(parents=True)
            inp = rc / "in.csv"
            inp.write_text(
                "domain,brand,legal_entity,parent_company,jurisdiction,company_number,"
                "provider_mentions,cashier_path,script_domains,support_widget,title_phrase,"
                "footer_phrase,analytics_ids,contact_email,mailing_address,notes,sources\n"
                "a.example,A,,ClusterParent,,,,,,,,,,,,n1,s1\n"
                "b.example,B,,ClusterParent,,,,,,,,,,,,n2,s2\n",
                encoding="utf-8",
            )
            run_stage(inp, rc, None)
            rels = json.loads((rc / "staged_relationships.json").read_text(encoding="utf-8"))[
                "relationships"
            ]
            clusters = [r for r in rels if r.get("source") == "research_cluster_corporate"]
            self.assertTrue(len(clusters) >= 1)
            self.assertEqual(clusters[0]["review_status"], "needs_review")

    def test_affiliation_dump_resolves_domains(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rc = root / "research_candidates"
            rc.mkdir(parents=True)
            inp = rc / "in.csv"
            inp.write_text(
                "domain,brand,legal_entity,parent_company,jurisdiction,company_number,"
                "provider_mentions,cashier_path,script_domains,support_widget,title_phrase,"
                "footer_phrase,analytics_ids,contact_email,mailing_address,notes,sources\n"
                "a.example,A,,,,,,,,,,,,,,,n,s\n"
                "b.example,B,,,,,,,,,,,,,,,n,s\n",
                encoding="utf-8",
            )
            aff = rc / "claude_affiliations_dump.json"
            aff.write_text(
                json.dumps(
                    [
                        {
                            "from_domain": "a.example",
                            "to_domain": "b.example",
                            "relationship": "related_to",
                            "confidence": 0.7,
                            "notes": "cluster per research",
                            "sources": "dump",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            run_stage(inp, rc, aff)
            rels = json.loads((rc / "staged_relationships.json").read_text(encoding="utf-8"))[
                "relationships"
            ]
            dumped = [r for r in rels if r.get("source") == "claude_affiliations_dump"]
            self.assertEqual(len(dumped), 1)
            self.assertEqual(dumped[0]["resolution_status"], "resolved")
            self.assertIsNotNone(dumped[0]["from_candidate_id"])


class TestPromote(unittest.TestCase):
    def test_only_approved_in_preview(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rc = root / "research_candidates"
            rc.mkdir(parents=True)
            (rc / "staged_entities.json").write_text(
                json.dumps(
                    {
                        "entities": [
                            {
                                "candidate_id": "research_0001",
                                "review_status": "approved",
                                "evidence_tier": "first_party_verified",
                                "domain": "x.example",
                                "brand": "X",
                                "legal_entity": "LE",
                                "parent_company": "",
                                "jurisdiction": "US",
                                "company_number": "",
                                "notes": "ok",
                                "sources": "u",
                                "sources_list": ["u"],
                                "raw_row": {"provider_mentions": "Pragmatic Play"},
                            },
                            {
                                "candidate_id": "research_0002",
                                "review_status": "needs_review",
                                "evidence_tier": "inferred_or_unverified",
                                "domain": "y.example",
                                "brand": "Y",
                                "legal_entity": "",
                                "parent_company": "",
                                "jurisdiction": "",
                                "company_number": "",
                                "notes": "no",
                                "sources": "",
                                "sources_list": [],
                                "raw_row": {},
                            },
                        ],
                        "generated_at": "t",
                    }
                ),
                encoding="utf-8",
            )
            (rc / "staged_fingerprints.json").write_text(
                json.dumps(
                    {
                        "fingerprints": [
                            {
                                "candidate_id": "research_0001",
                                "review_status": "needs_review",
                                "evidence_tier": "first_party_verified",
                                "technical": {"analytics_ids": ["g-1"], "script_domains": []},
                                "content": {
                                    "title_terms": ["t"],
                                    "footer_phrases": [],
                                    "provider_mentions": [],
                                },
                                "flow": {"cashier_paths": []},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (rc / "staged_relationships.json").write_text(
                json.dumps({"relationships": []}),
                encoding="utf-8",
            )
            pv = rc / "preview"
            self.assertEqual(run_promote(rc, pv, apply_to_seeds=False), 0)
            with (pv / "proposed_operators.csv").open(encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["domain"], "x.example")
            self.assertEqual(rows[0]["status"], "inactive")

    def test_apply_to_seeds_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rc = Path(td) / "rc"
            rc.mkdir()
            (rc / "staged_entities.json").write_text(
                json.dumps({"entities": []}), encoding="utf-8"
            )
            (rc / "staged_fingerprints.json").write_text(
                json.dumps({"fingerprints": []}), encoding="utf-8"
            )
            (rc / "staged_relationships.json").write_text(
                json.dumps({"relationships": []}), encoding="utf-8"
            )
            self.assertEqual(run_promote(rc, rc / "pv", apply_to_seeds=True), 2)


if __name__ == "__main__":
    unittest.main()
