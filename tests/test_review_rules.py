from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from intel.review_rules import (
    decision_for_staged_entity,
    run_review_rules,
)


def _minimal_norm_index() -> dict:
    return {
        "legal_to_ids": {},
        "parent_to_ids": {},
        "domain_to_id": {},
        "company_no_to_ids": {},
    }


class TestEntityTypeHints(unittest.TestCase):
    def test_operator_from_sweeps_terms(self) -> None:
        ent = {
            "candidate_id": "r1",
            "domain": "play.brand.example",
            "legal_entity": "Brand LLC",
            "parent_company": "",
            "notes": "Official sweeps and social casino site.",
            "sources": "https://play.brand.example",
            "evidence_tier": "first_party_verified",
            "raw_row": {},
        }
        d = decision_for_staged_entity(
            ent,
            {},
            norm_index=_minimal_norm_index(),
            staged_clusters=[],
            rel_promotes={},
            rel_uses_provider={},
        )
        self.assertEqual(d["likely_entity_type"], "operator")
        self.assertTrue(any("rule:operator_term_hits" in x for x in d["reasoning"]))

    def test_promoter_from_affiliate_language(self) -> None:
        ent = {
            "candidate_id": "r2",
            "domain": "reviews.example",
            "legal_entity": "",
            "parent_company": "",
            "notes": "Top sweeps comparison and bonus guide with promo codes. Affiliate disclosure.",
            "sources": "",
            "evidence_tier": "secondary_corroborated",
            "raw_row": {},
        }
        d = decision_for_staged_entity(
            ent,
            {},
            norm_index=_minimal_norm_index(),
            staged_clusters=[],
            rel_promotes={},
            rel_uses_provider={},
        )
        self.assertEqual(d["likely_entity_type"], "promoter")

    def test_provider_from_raw_and_relationships(self) -> None:
        ent = {
            "candidate_id": "r3",
            "domain": "studio.example",
            "legal_entity": "Studio AG",
            "parent_company": "",
            "notes": "Game provider and slot studio.",
            "sources": "",
            "evidence_tier": "first_party_verified",
            "raw_row": {"entity_type": "provider", "provider_type": "studio"},
        }
        d = decision_for_staged_entity(
            ent,
            {},
            norm_index=_minimal_norm_index(),
            staged_clusters=[],
            rel_promotes={},
            rel_uses_provider={"r3": 3},
        )
        self.assertEqual(d["likely_entity_type"], "provider")


class TestFieldConfidence(unittest.TestCase):
    def test_first_party_legal_high_parent_downgraded_when_reported(self) -> None:
        ent = {
            "candidate_id": "r4",
            "domain": "casino.example",
            "legal_entity": "Real Co",
            "parent_company": "Reported parent",
            "notes": "Legal from terms; parent_company reported only not verified.",
            "sources": "https://casino.example/terms",
            "evidence_tier": "first_party_verified",
            "raw_row": {},
        }
        d = decision_for_staged_entity(
            ent,
            {},
            norm_index=_minimal_norm_index(),
            staged_clusters=[],
            rel_promotes={},
            rel_uses_provider={},
        )
        self.assertEqual(d["field_confidence"]["legal_entity"], "high")
        self.assertEqual(d["field_confidence"]["parent_company"], "medium")


class TestPromotionRecommendation(unittest.TestCase):
    def test_promote_now_when_strong(self) -> None:
        ent = {
            "candidate_id": "r5",
            "domain": "realbrand.example",
            "legal_entity": "RealBrand Inc",
            "parent_company": "",
            "notes": "quoted verbatim from official terms; sweeps rules",
            "sources": "https://realbrand.example/terms",
            "evidence_tier": "first_party_verified",
            "raw_row": {},
        }
        d = decision_for_staged_entity(
            ent,
            {},
            norm_index=_minimal_norm_index(),
            staged_clusters=[],
            rel_promotes={},
            rel_uses_provider={},
        )
        self.assertEqual(d["promotion_recommendation"], "promote_now")

    def test_stage_only_on_403_secondary(self) -> None:
        ent = {
            "candidate_id": "r6",
            "domain": "edge.example",
            "legal_entity": "Edge LLC",
            "parent_company": "",
            "notes": "403 on main site; corroborated by third-party reporting",
            "sources": "https://edge.example",
            "evidence_tier": "secondary_corroborated",
            "raw_row": {},
        }
        d = decision_for_staged_entity(
            ent,
            {},
            norm_index=_minimal_norm_index(),
            staged_clusters=[],
            rel_promotes={},
            rel_uses_provider={},
        )
        self.assertEqual(d["promotion_recommendation"], "stage_only")
        self.assertIn("rule:promotion_stage_403_secondary", d["reasoning"])

    def test_reject_placeholder_domain(self) -> None:
        ent = {
            "candidate_id": "r7",
            "domain": "example.com",
            "legal_entity": "X",
            "parent_company": "",
            "notes": "sweeps casino",
            "sources": "",
            "evidence_tier": "first_party_verified",
            "raw_row": {},
        }
        d = decision_for_staged_entity(
            ent,
            {},
            norm_index=_minimal_norm_index(),
            staged_clusters=[],
            rel_promotes={},
            rel_uses_provider={},
        )
        self.assertEqual(d["promotion_recommendation"], "reject_for_now")


class TestClusterRecommendation(unittest.TestCase):
    def test_attach_on_shared_legal_entity(self) -> None:
        norm_index = {
            "legal_to_ids": {"acme holdco llc": ["operator_existing"]},
            "parent_to_ids": {},
            "domain_to_id": {},
            "company_no_to_ids": {},
        }
        ent = {
            "candidate_id": "r8",
            "domain": "newskin.example",
            "legal_entity": "Acme HoldCo LLC",
            "parent_company": "",
            "notes": "sweeps",
            "sources": "",
            "evidence_tier": "first_party_verified",
            "raw_row": {},
        }
        d = decision_for_staged_entity(
            ent,
            {},
            norm_index=norm_index,
            staged_clusters=[],
            rel_promotes={},
            rel_uses_provider={},
        )
        self.assertEqual(d["cluster_recommendation"], "attach_to_existing_cluster")


class TestTightenedBlockRules(unittest.TestCase):
    def test_confirmed_catalog_operator_block_now_even_inferred(self) -> None:
        ent = {
            "candidate_id": "seedop",
            "domain": "chumbacasino.com",
            "legal_entity": "",
            "parent_company": "",
            "notes": "",
            "sources": "https://www.chumbacasino.com/",
            "evidence_tier": "inferred_or_unverified",
            "raw_row": {},
        }
        d = decision_for_staged_entity(
            ent,
            {},
            norm_index=_minimal_norm_index(),
            staged_clusters=[],
            rel_promotes={},
            rel_uses_provider={},
            confirmed_operator_domains=frozenset({"chumbacasino.com"}),
        )
        self.assertEqual(d["likely_entity_type"], "operator")
        self.assertEqual(d["block_recommendation"], "block_now")
        self.assertIn("rule:block_now_confirmed_operator_seed_or_catalog", d["reasoning"])

    def test_redirect_shell_inferred_operator_block_now_with_strong_signals(self) -> None:
        ent = {
            "candidate_id": "sh",
            "domain": "shell.example",
            "legal_entity": "",
            "parent_company": "",
            "notes": "Rebrand redirect; gold coins and sweeps coins games.",
            "sources": "",
            "evidence_tier": "inferred_or_unverified",
            "raw_row": {},
        }
        d = decision_for_staged_entity(
            ent,
            {},
            norm_index=_minimal_norm_index(),
            staged_clusters=[],
            rel_promotes={},
            rel_uses_provider={},
            confirmed_operator_domains=frozenset(),
        )
        self.assertEqual(d["likely_entity_type"], "operator")
        self.assertEqual(d["block_recommendation"], "block_now")
        self.assertIn("rule:block_now_redirect_shell_operator", d["reasoning"])

    def test_promoter_stays_do_not_block(self) -> None:
        ent = {
            "candidate_id": "pr",
            "domain": "reviews.example",
            "legal_entity": "",
            "parent_company": "",
            "notes": "Top sweeps comparison site; affiliate links and bonus guide.",
            "sources": "",
            "evidence_tier": "first_party_verified",
            "raw_row": {},
        }
        d = decision_for_staged_entity(
            ent,
            {},
            norm_index=_minimal_norm_index(),
            staged_clusters=[],
            rel_promotes={},
            rel_uses_provider={},
        )
        self.assertEqual(d["likely_entity_type"], "promoter")
        self.assertEqual(d["block_recommendation"], "do_not_block")

    def test_provider_stays_do_not_block(self) -> None:
        ent = {
            "candidate_id": "pv",
            "domain": "studio.example",
            "legal_entity": "Studio AG",
            "parent_company": "",
            "notes": "Slot studio and game provider for operators.",
            "sources": "",
            "evidence_tier": "first_party_verified",
            "raw_row": {"entity_type": "provider", "provider_type": "studio"},
        }
        d = decision_for_staged_entity(
            ent,
            {},
            norm_index=_minimal_norm_index(),
            staged_clusters=[],
            rel_promotes={},
            rel_uses_provider={},
        )
        self.assertEqual(d["likely_entity_type"], "provider")
        self.assertEqual(d["block_recommendation"], "do_not_block")


class TestBlockRecommendation(unittest.TestCase):
    def test_redirect_shell_operator_first_party_block_now(self) -> None:
        ent = {
            "candidate_id": "r9",
            "domain": "redirectshell.example",
            "legal_entity": "Shell LLC",
            "parent_company": "",
            "notes": "Rebrand redirect from legacy sweeps casino domain per official statement",
            "sources": "https://redirectshell.example",
            "evidence_tier": "first_party_verified",
            "raw_row": {},
        }
        d = decision_for_staged_entity(
            ent,
            {},
            norm_index=_minimal_norm_index(),
            staged_clusters=[],
            rel_promotes={},
            rel_uses_provider={},
        )
        self.assertEqual(d["likely_entity_type"], "operator")
        self.assertEqual(d["block_recommendation"], "block_now")
        self.assertIn("rule:block_now_redirect_shell_operator", d["reasoning"])

    def test_operator_secondary_block_after_review(self) -> None:
        ent = {
            "candidate_id": "r10",
            "domain": "mixed.example",
            "legal_entity": "Mixed LLC",
            "parent_company": "",
            "notes": "Social casino; corroborated by third-party reporting only",
            "sources": "",
            "evidence_tier": "secondary_corroborated",
            "raw_row": {},
        }
        d = decision_for_staged_entity(
            ent,
            {},
            norm_index=_minimal_norm_index(),
            staged_clusters=[],
            rel_promotes={},
            rel_uses_provider={},
        )
        self.assertEqual(d["block_recommendation"], "block_after_review")


class TestRunReviewRulesWritesFiles(unittest.TestCase):
    def test_writes_decisions_and_report(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data" / "normalized").mkdir(parents=True)
            (root / "data" / "research_candidates").mkdir(parents=True)
            (root / "data" / "normalized" / "entities.json").write_text("[]", encoding="utf-8")
            (root / "data" / "research_candidates" / "staged_entities.json").write_text(
                json.dumps({"entities": []}), encoding="utf-8"
            )
            for name, body in (
                ("staged_fingerprints.json", {"fingerprints": []}),
                ("staged_relationships.json", {"relationships": []}),
                ("staged_clusters.json", {"clusters": []}),
                ("review_queue.json", {"items": []}),
            ):
                (root / "data" / "research_candidates" / name).write_text(
                    json.dumps(body), encoding="utf-8"
                )
            r = run_review_rules(root)
            self.assertTrue(Path(r["output"]).is_file())
            self.assertTrue(Path(r["report"]).is_file())
            doc = json.loads(Path(r["output"]).read_text(encoding="utf-8"))
            self.assertIn("decisions", doc)


if __name__ == "__main__":
    unittest.main()
