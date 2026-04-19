from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from intel.affiliations import run_affiliations
from intel.enrich import (
    dedupe_sorted_strings,
    empty_fingerprint_dict,
    extract_signals_from_html,
    merge_manual_row_into_fingerprint,
    merge_string_lists,
    normalize_fingerprint_dict,
    run_enrich,
)


class TestMergeManual(unittest.TestCase):
    def test_merge_manual_row_merges_and_skips_empty(self) -> None:
        fp = empty_fingerprint_dict("e1")
        fp["technical"]["analytics_ids"] = ["existing"]
        merge_manual_row_into_fingerprint(
            fp,
            {
                "entity_id": "e1",
                "analytics_ids": "G-B|G-A",
                "script_domains": "cdn.example.com",
                "footer_phrases": "",
                "cashier_paths": "/pay|/pay",
            },
        )
        self.assertEqual(
            fp["technical"]["analytics_ids"],
            ["existing", "g-a", "g-b"],
        )
        self.assertEqual(fp["technical"]["script_domains"], ["cdn.example.com"])
        self.assertEqual(fp["flow"]["cashier_paths"], ["/pay"])

    def test_normalize_sorts_deterministically(self) -> None:
        fp = empty_fingerprint_dict("x")
        fp["technical"]["script_domains"] = ["z.com", "a.com", "a.com"]
        normalize_fingerprint_dict(fp)
        self.assertEqual(fp["technical"]["script_domains"], ["a.com", "z.com"])


class TestDedupe(unittest.TestCase):
    def test_merge_string_lists(self) -> None:
        self.assertEqual(
            merge_string_lists(["b", "a"], ["a", "c"], lower_domains=True),
            ["a", "b", "c"],
        )

    def test_dedupe_sorted_strings(self) -> None:
        self.assertEqual(
            dedupe_sorted_strings(["Z", "a", "A"], lower=True),
            ["a", "Z"],
        )


class TestHTMLExtract(unittest.TestCase):
    def test_script_iframe_asset_domains(self) -> None:
        html = """<!doctype html><html><head>
        <title>My Casino Home Page</title>
        <script src="https://cdn.vendor.com/track.js"></script>
        <script>gtag('config', 'G-UNITTEST123');</script>
        </head><body>
        <iframe src="https://frames.example.com/embed"></iframe>
        <img src="https://img.cdn.test/i.png">
        <footer>All rights reserved by Test Legal Name LLC</footer>
        </body></html>"""
        ext = extract_signals_from_html(html, "https://example.com/", ["Pragmatic Play"])
        self.assertIn("cdn.vendor.com", ext["technical"]["script_domains"])
        self.assertIn("frames.example.com", ext["technical"]["iframe_domains"])
        self.assertIn("img.cdn.test", ext["technical"]["asset_domains"])
        self.assertIn("g-unittest123", ext["technical"]["analytics_ids"])
        self.assertTrue(any("casino" in t for t in ext["content"]["title_terms"]))
        self.assertTrue(any("legal" in f.lower() for f in ext["content"]["footer_phrases"]))


class TestAffiliationsAfterEnrich(unittest.TestCase):
    def test_shared_fingerprints_yield_affiliations(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            norm = root / "normalized"
            norm.mkdir()
            seeds = root / "seeds"
            seeds.mkdir()
            entities = [
                {
                    "id": "operator_a",
                    "name": "A",
                    "entity_type": "operator",
                    "domains": ["a.example"],
                    "categories": [],
                    "status": "active",
                    "confidence": 1.0,
                    "sources": [],
                    "notes": "",
                    "first_seen": "2026-01-01T00:00:00Z",
                    "last_seen": "2026-01-01T00:00:00Z",
                    "attributes": {"legal_entity": "", "jurisdictions": [], "blockable": True, "evidence_only": False, "provider_names": []},
                },
                {
                    "id": "operator_b",
                    "name": "B",
                    "entity_type": "operator",
                    "domains": ["b.example"],
                    "categories": [],
                    "status": "active",
                    "confidence": 1.0,
                    "sources": [],
                    "notes": "",
                    "first_seen": "2026-01-01T00:00:00Z",
                    "last_seen": "2026-01-01T00:00:00Z",
                    "attributes": {"legal_entity": "", "jurisdictions": [], "blockable": True, "evidence_only": False, "provider_names": []},
                },
            ]
            fps = [empty_fingerprint_dict("operator_a"), empty_fingerprint_dict("operator_b")]
            (norm / "entities.json").write_text(json.dumps(entities), encoding="utf-8")
            (norm / "fingerprints.json").write_text(json.dumps(fps), encoding="utf-8")
            (norm / "relationships.json").write_text(json.dumps([]), encoding="utf-8")

            (seeds / "fingerprints_partial.csv").write_text(
                "entity_id,analytics_ids,cashier_paths,provider_mentions\n"
                "operator_a,G-SHARED-XYZ,,Pragmatic Play\n"
                "operator_b,G-SHARED-XYZ,/cashier/deposit,\n",
                encoding="utf-8",
            )
            run_enrich(root, norm, seeds, fetch=False, report_dir=root / "reports")

            out_fp = json.loads((norm / "fingerprints.json").read_text(encoding="utf-8"))
            by_eid = {x["entity_id"]: x for x in out_fp}
            self.assertIn("g-shared-xyz", by_eid["operator_a"]["technical"]["analytics_ids"])
            self.assertIn("/cashier/deposit", by_eid["operator_b"]["flow"]["cashier_paths"])

            aff_out = norm / "affiliations.json"
            run_affiliations(norm, aff_out)
            aff = json.loads(aff_out.read_text(encoding="utf-8"))
            self.assertTrue(len(aff) >= 1)
            pair = aff[0]
            self.assertGreaterEqual(pair["score"], 40)
            types = {e["type"] for e in pair["evidence"]}
            self.assertTrue("shared_analytics_or_tag" in types or "shared_cashier_pattern" in types)


if __name__ == "__main__":
    unittest.main()
