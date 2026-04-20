from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from intel.import_scout_candidates import run_import_scout_candidates
from intel.review_scout_candidates import run_review_scout_candidates


class TestScoutImport(unittest.TestCase):
    def test_import_preserves_provenance_and_stages_redirects_separately(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scout = root / "scout_import"
            out = root / "staged_from_scout"
            scout.mkdir(parents=True)

            corp = scout / "corporate_entities_candidates.csv"
            with corp.open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(
                    f,
                    fieldnames=[
                        "name",
                        "legal_entity",
                        "primary_domain",
                        "confidence",
                        "source_set",
                        "merge_notes",
                        "notes",
                        "sources",
                    ],
                )
                w.writeheader()
                w.writerow(
                    {
                        "name": "HoldCo",
                        "legal_entity": "Example HoldCo LLC",
                        "primary_domain": "holdco.example",
                        "confidence": "0.95",
                        "source_set": "batch_a",
                        "merge_notes": "",
                        "notes": "official corporate listing",
                        "sources": "https://holdco.example",
                    }
                )

            ops = scout / "operators_candidates.csv"
            with ops.open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(
                    f,
                    fieldnames=[
                        "brand",
                        "primary_domain",
                        "other_domains",
                        "duplicate_group_id",
                        "is_canonical",
                        "confidence",
                        "notes",
                    ],
                )
                w.writeheader()
                w.writerow(
                    {
                        "brand": "Funz",
                        "primary_domain": "funzcity.com",
                        "other_domains": "funzcity.net",
                        "duplicate_group_id": "g_funz",
                        "is_canonical": "true",
                        "confidence": "0.9",
                        "notes": "canonical row",
                    }
                )
                w.writerow(
                    {
                        "brand": "Funz Alt",
                        "primary_domain": "funzcity.net",
                        "other_domains": "",
                        "duplicate_group_id": "g_funz",
                        "is_canonical": "false",
                        "confidence": "0.85",
                        "notes": "alias candidate",
                    }
                )

            pro = scout / "promoters_candidates.csv"
            with pro.open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["name", "primary_domain", "confidence", "notes"])
                w.writeheader()
                w.writerow(
                    {
                        "name": "ReviewSite",
                        "primary_domain": "reviews.example",
                        "confidence": "0.8",
                        "notes": "affiliate comparison",
                    }
                )

            red = scout / "redirects_rebrands_candidates.csv"
            with red.open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(
                    f, fieldnames=["from_domain", "to_domain", "notes", "confidence"]
                )
                w.writeheader()
                w.writerow(
                    {
                        "from_domain": "old.example",
                        "to_domain": "new.example",
                        "notes": "rebrand redirect",
                        "confidence": "0.7",
                    }
                )

            r = run_import_scout_candidates(root, scout_dir=scout, out_dir=out)
            self.assertEqual(r["entity_count"], 4)
            self.assertEqual(r["redirect_count"], 1)
            self.assertEqual(r["relationship_count"], 1)

            ent_doc = json.loads((out / "staged_entities.json").read_text(encoding="utf-8"))
            corps = [e for e in ent_doc["entities"] if e["entity_type_hint"] == "corporate"]
            self.assertEqual(len(corps), 1)
            self.assertEqual(corps[0]["imported_from"], "scout")
            self.assertEqual(corps[0]["raw_source_file"], "corporate_entities_candidates.csv")
            self.assertEqual(corps[0]["source_set"], "batch_a")
            self.assertIn("legal_entity", corps[0]["raw_row"])

            op_rows = [e for e in ent_doc["entities"] if e["entity_type_hint"] == "operator"]
            alias_row = next(x for x in op_rows if "funzcity.com" in x.get("primary_domain", ""))
            self.assertTrue(alias_row["alias_candidates_non_empty"])
            self.assertEqual(alias_row["alias_review_status"], "needs_manual_verification")

            red_doc = json.loads((out / "staged_redirects.json").read_text(encoding="utf-8"))
            self.assertEqual(len(red_doc["redirects"]), 1)
            self.assertEqual(red_doc["redirects"][0]["imported_from"], "scout")
            self.assertEqual(red_doc["redirects"][0]["raw_source_file"], "redirects_rebrands_candidates.csv")

            rel_doc = json.loads((out / "staged_relationships.json").read_text(encoding="utf-8"))
            self.assertEqual(rel_doc["relationships"][0]["relationship_type"], "duplicate_alias_candidate")
            self.assertEqual(rel_doc["relationships"][0]["duplicate_group_id"], "g_funz")

    def test_review_summary_counts_and_alias_manual(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scout = root / "scout_import"
            out = root / "staged_from_scout"
            scout.mkdir(parents=True)
            corp = scout / "corporate_entities_candidates.csv"
            with corp.open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(
                    f, fieldnames=["name", "primary_domain", "confidence", "notes", "other_domains"]
                )
                w.writeheader()
                w.writerow(
                    {
                        "name": "PureCorp",
                        "primary_domain": "corp.example",
                        "confidence": "0.99",
                        "notes": "clean",
                        "other_domains": "",
                    }
                )
            ops = scout / "operators_candidates.csv"
            with ops.open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(
                    f, fieldnames=["brand", "primary_domain", "other_domains", "confidence", "notes"]
                )
                w.writeheader()
                w.writerow(
                    {
                        "brand": "Op",
                        "primary_domain": "op.example",
                        "other_domains": "alias.example",
                        "confidence": "0.9",
                        "notes": "x",
                    }
                )
            for name in ("promoters_candidates.csv", "redirects_rebrands_candidates.csv"):
                p = scout / name
                with p.open("w", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=["primary_domain"])
                    w.writeheader()

            run_import_scout_candidates(root, scout_dir=scout, out_dir=out)
            rev = run_review_scout_candidates(root, staged_dir=out)
            self.assertEqual(rev["counts"]["staged_corporate_entities"], 1)
            self.assertEqual(rev["counts"]["staged_operators"], 1)
            self.assertEqual(rev["counts"]["rows_with_alias_or_other_domains"], 1)
            summary = json.loads((out / "promotion_review_summary.json").read_text(encoding="utf-8"))
            corp_rec = next(
                x for x in summary["entity_promotion_rows"] if x["entity_type_hint"] == "corporate"
            )
            self.assertEqual(corp_rec["promotion_recommendation"], "safe_to_promote_now")
            op_rec = next(
                x for x in summary["entity_promotion_rows"] if x["entity_type_hint"] == "operator"
            )
            self.assertEqual(op_rec["promotion_recommendation"], "needs_manual_verification")


if __name__ == "__main__":
    unittest.main()
