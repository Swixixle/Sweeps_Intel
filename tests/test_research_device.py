from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from intel.cluster import run_cluster
from intel.discover import run_discover
from intel.enrich import extract_signals_from_html
from intel.review_queue import run_review_queue


class TestDiscoverDedupe(unittest.TestCase):
    @patch("intel.discover.fetch_url")
    def test_outbound_domain_merges_sources(self, mock_fetch) -> None:
        html = '<html><a href="https://partner.example/out">x</a></html>'

        def side_effect(url: str):
            u = url.lower()
            if "seed-a" in u:
                return ("https://seed-a.example/page", html.replace("partner.example", "shared.io"), 200)
            if "seed-b" in u:
                return ("https://seed-b.example/", html.replace("partner.example", "shared.io"), 200)
            return (url, html, 200)

        mock_fetch.side_effect = side_effect
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            seeds = root / "seed_urls.txt"
            seeds.write_text(
                "https://seed-a.example/start\nhttps://seed-b.example/\n", encoding="utf-8"
            )
            cand = root / "candidates"
            reps = root / "reports"
            run_discover(
                root,
                seeds_path=seeds,
                candidates_dir=cand,
                reports_dir=reps,
                max_depth=0,
                max_same_host_pages=5,
                denylist_path=None,
                allowlist_path=None,
            )
            doms = json.loads((cand / "discovered_domains.json").read_text(encoding="utf-8"))
            by_dom = {d["domain"]: d for d in doms}
            self.assertIn("shared.io", by_dom)
            self.assertGreaterEqual(len(by_dom["shared.io"]["source_urls"]), 2)


class TestExtractSampleHtml(unittest.TestCase):
    def test_scripts_iframes_and_legal_links(self) -> None:
        html = """<!doctype html>
<html><head><title>Test Casino Fun</title>
<script src="https://cdn.tracker.example/p.js"></script></head>
<body>
<iframe src="https://embed.games.example/lobby"></iframe>
<a href="/terms-of-service">Terms</a>
<a href="https://support.example.com/hc/en-us">Help</a>
</body></html>"""
        ext = extract_signals_from_html(html, "https://brand.example/", [])
        tech = ext["technical"]
        self.assertIn("cdn.tracker.example", tech["script_domains"])
        self.assertIn("embed.games.example", tech["iframe_domains"])
        self.assertIn("casino", ext["content"]["title_terms"])


class TestClusterToyData(unittest.TestCase):
    def test_same_legal_entity_groups_domains(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data" / "normalized").mkdir(parents=True)
            (root / "data" / "research_candidates").mkdir(parents=True)
            ents = [
                {
                    "id": "op_a",
                    "entity_type": "operator",
                    "domains": ["aaa.example"],
                    "attributes": {"legal_entity": "Same HoldCo LLC"},
                },
                {
                    "id": "op_b",
                    "entity_type": "operator",
                    "domains": ["bbb.example"],
                    "attributes": {"legal_entity": "Same HoldCo LLC"},
                },
            ]
            fps = [
                {"entity_id": "op_a", "technical": {"script_domains": ["z.com", "y.com"]}},
                {"entity_id": "op_b", "technical": {"script_domains": ["z.com", "y.com"]}},
            ]
            (root / "data" / "normalized" / "entities.json").write_text(
                json.dumps(ents), encoding="utf-8"
            )
            (root / "data" / "normalized" / "fingerprints.json").write_text(
                json.dumps(fps), encoding="utf-8"
            )
            r = run_cluster(root, min_script_overlap=2)
            doc = json.loads(
                (root / "data" / "research_candidates" / "staged_clusters.json").read_text(
                    encoding="utf-8"
                )
            )
            clusters = doc.get("clusters") or []
            self.assertTrue(clusters)
            members = set(clusters[0].get("members") or [])
            self.assertTrue({"aaa.example", "bbb.example"}.issubset(members))
            self.assertGreaterEqual(r.get("cluster_count", 0), 1)


class TestReviewQueueOrder(unittest.TestCase):
    def test_higher_tier_sorts_first(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rc = root / "data" / "research_candidates"
            rc.mkdir(parents=True)
            (rc / "staged_entities.json").write_text(
                json.dumps(
                    {
                        "entities": [
                            {
                                "candidate_id": "weak",
                                "review_status": "needs_review",
                                "evidence_tier": "inferred_or_unverified",
                                "domain": "weak.example",
                                "legal_entity": "",
                                "parent_company": "",
                                "notes": "guess",
                                "sources": "",
                            },
                            {
                                "candidate_id": "strong",
                                "review_status": "needs_review",
                                "evidence_tier": "first_party_verified",
                                "domain": "strong.example",
                                "legal_entity": "Official Co",
                                "parent_company": "",
                                "notes": "quoted verbatim from official terms",
                                "sources": "https://strong.example/terms",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            for fname, body in (
                ("staged_fingerprints.json", {"fingerprints": [], "generated_at": "x"}),
                ("staged_relationships.json", {"relationships": [], "generated_at": "x"}),
                ("extracted_fingerprints.json", {"fingerprints": [], "generated_at": "x"}),
                ("staged_clusters.json", {"clusters": [], "generated_at": "x"}),
            ):
                (rc / fname).write_text(json.dumps(body), encoding="utf-8")
            (root / "data" / "candidates").mkdir(parents=True)
            (root / "data" / "candidates" / "discovered_domains.json").write_text(
                "[]", encoding="utf-8"
            )
            run_review_queue(root)
            q = json.loads((rc / "review_queue.json").read_text(encoding="utf-8"))
            kinds_ids = [(x["kind"], x["id"]) for x in q["items"] if x["kind"] == "staged_entity"]
            self.assertGreaterEqual(len(kinds_ids), 2)
            first_staged = next(x for x in q["items"] if x["kind"] == "staged_entity")
            self.assertEqual(first_staged["id"], "strong")


if __name__ == "__main__":
    unittest.main()
