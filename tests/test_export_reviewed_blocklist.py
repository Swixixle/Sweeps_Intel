from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from intel.export_reviewed_blocklist import run_export_reviewed_blocklist


class TestExportReviewedBlocklist(unittest.TestCase):
    def test_block_now_emits_domains_and_cluster_members(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rc = root / "data" / "research_candidates"
            rc.mkdir(parents=True)
            (rc / "review_decisions.json").write_text(
                json.dumps(
                    {
                        "decisions": [
                            {
                                "record_id": "queue:discovered_domain:bad.example",
                                "source_type": "entity",
                                "block_recommendation": "block_now",
                                "likely_entity_type": "operator",
                            },
                            {
                                "record_id": "cluster-x",
                                "source_type": "cluster",
                                "block_recommendation": "block_now",
                                "likely_entity_type": "unknown",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (rc / "staged_clusters.json").write_text(
                json.dumps(
                    {
                        "clusters": [
                            {
                                "cluster_id": "cluster-x",
                                "members": ["a.example", "b.example"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (rc / "staged_entities.json").write_text(
                json.dumps({"entities": []}),
                encoding="utf-8",
            )
            r = run_export_reviewed_blocklist(root)
            self.assertEqual(r["domain_count"], 3)
            doc = json.loads((root / "data" / "published" / "reviewed_blocklist.json").read_text())
            self.assertEqual(set(doc["domains"]), {"bad.example", "a.example", "b.example"})
            txt = (root / "data" / "published" / "reviewed_domains.txt").read_text()
            self.assertIn("bad.example", txt)

    def test_after_review_only_when_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rc = root / "data" / "research_candidates"
            rc.mkdir(parents=True)
            (rc / "review_decisions.json").write_text(
                json.dumps(
                    {
                        "decisions": [
                            {
                                "record_id": "queue:discovered_domain:late.example",
                                "source_type": "entity",
                                "block_recommendation": "block_after_review",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (rc / "staged_clusters.json").write_text(json.dumps({"clusters": []}), encoding="utf-8")
            (rc / "staged_entities.json").write_text(json.dumps({"entities": []}), encoding="utf-8")
            r0 = run_export_reviewed_blocklist(root, include_after_review=False)
            self.assertEqual(r0["domain_count"], 0)
            r1 = run_export_reviewed_blocklist(root, include_after_review=True)
            self.assertEqual(r1["domain_count"], 1)


if __name__ == "__main__":
    unittest.main()
