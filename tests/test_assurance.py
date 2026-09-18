import importlib.util
import json
import pathlib
import sys
import unittest

MODULE = pathlib.Path(__file__).parents[1] / "extensions" / "commands" / "cmd_assurance.py"
SPEC = importlib.util.spec_from_file_location("cmd_assurance", MODULE)
assurance = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = assurance
SPEC.loader.exec_module(assurance)


class AssuranceTests(unittest.TestCase):
    def test_github_release_url_resolves(self):
        self.assertEqual(
            assurance.canonical_github_project(
                "https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz"
            ),
            "github.com/madler/zlib",
        )

    def test_codeload_url_resolves(self):
        self.assertEqual(
            assurance.canonical_github_project(
                "https://codeload.github.com/openssl/openssl/tar.gz/refs/tags/openssl-3.3.0"
            ),
            "github.com/openssl/openssl",
        )

    def test_non_github_url_does_not_resolve(self):
        self.assertIsNone(
            assurance.canonical_github_project("https://zlib.net/zlib-1.3.1.tar.gz")
        )

    def test_source_digest_passes_with_sha256(self):
        node = {
            "ref": "zlib/1.3.1#abc",
            "name": "zlib",
            "version": "1.3.1",
            "rrev": "abc",
            "conandata": {
                "sources": {
                    "1.3.1": {
                        "url": [
                            "https://zlib.net/fossils/zlib-1.3.1.tar.gz",
                            "https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz",
                        ],
                        "sha256": "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23",
                    }
                }
            },
        }
        item = assurance._source_digest_evidence("zlib/1.3.1", node)
        self.assertEqual(item.status, "PASS")
        self.assertEqual(len(item.locations), 2)

    def test_source_digest_fails_when_url_unpinned(self):
        node = {
            "name": "demo",
            "version": "1.0",
            "conandata": {
                "sources": {
                    "1.0": {
                        "url": "https://example.test/demo-1.0.tar.gz",
                    }
                }
            },
        }
        item = assurance._source_digest_evidence("demo/1.0", node)
        self.assertEqual(item.status, "FAIL")

    def test_graph_inspection_is_deterministic_without_network(self):
        graph = {
            "nodes": {
                "0": {"ref": "conanfile", "name": None, "version": None},
                "2": {
                    "ref": "b/2.0#bbbb",
                    "name": "b",
                    "version": "2.0",
                    "rrev": "bbbb",
                    "conandata": {},
                },
                "1": {
                    "ref": "a/1.0#aaaa",
                    "name": "a",
                    "version": "1.0",
                    "rrev": "aaaa",
                    "conandata": {},
                },
            }
        }
        evidence = assurance.inspect_graph(graph, skip_scorecard=True)
        keys = [(item.reference, item.check) for item in evidence]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len(evidence), 6)
        digest1 = assurance.evidence_digest(evidence)
        digest2 = assurance.evidence_digest(list(reversed(evidence)))
        self.assertEqual(digest1, digest2)

    def test_summary_counts_statuses(self):
        evidence = [
            assurance.Evidence("a/1", "x", "PASS", "ok"),
            assurance.Evidence("a/1", "y", "FAIL", "bad"),
            assurance.Evidence("a/1", "z", "UNKNOWN", "maybe"),
        ]
        result = assurance.summarize(evidence)
        self.assertEqual(result["packages"], 1)
        self.assertEqual(result["observations"], 3)
        self.assertEqual(result["counts"]["PASS"], 1)
        self.assertEqual(result["counts"]["FAIL"], 1)
        self.assertEqual(result["counts"]["UNKNOWN"], 1)


if __name__ == "__main__":
    unittest.main()
