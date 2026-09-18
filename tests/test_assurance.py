import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

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


    def test_source_artifact_bytes_pass_on_matching_download(self):
        expected = "a" * 64
        node = {
            "name": "demo",
            "version": "1.0",
            "conandata": {
                "sources": {
                    "1.0": {
                        "url": "https://example.test/demo-1.0.tar.gz",
                        "sha256": expected,
                    }
                }
            },
        }
        with mock.patch.object(
            assurance,
            "_download_sha256",
            return_value=(expected, 1234),
        ):
            item = assurance._source_artifact_evidence(
                "demo/1.0",
                node,
                timeout=1,
                max_bytes=4096,
            )

        self.assertEqual(item.status, "PASS")
        self.assertIn(f"sha256:{expected}", item.locations)
        self.assertIn("bytes:1234", item.locations)

    def test_source_artifact_bytes_fail_on_mismatch(self):
        node = {
            "name": "demo",
            "version": "1.0",
            "conandata": {
                "sources": {
                    "1.0": {
                        "url": "https://example.test/demo-1.0.tar.gz",
                        "sha256": "a" * 64,
                    }
                }
            },
        }
        with mock.patch.object(
            assurance,
            "_download_sha256",
            return_value=("b" * 64, 1234),
        ):
            item = assurance._source_artifact_evidence(
                "demo/1.0",
                node,
                timeout=1,
                max_bytes=4096,
            )

        self.assertEqual(item.status, "FAIL")
        self.assertIn("mismatch", item.summary)

    def test_package_tree_digest_binds_paths_and_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "include").mkdir()
            (root / "lib").mkdir()
            (root / "include" / "demo.h").write_text("hello\n", encoding="utf-8")
            (root / "lib" / "libdemo.a").write_bytes(b"archive")
            digest1 = assurance._package_tree_digest(root)
            digest2 = assurance._package_tree_digest(root)

        self.assertEqual(digest1, digest2)
        self.assertEqual(digest1[1], 2)
        self.assertEqual(digest1[2], 13)
        self.assertEqual(len(digest1[0]), 64)

    def test_payload_digest_ignores_conan_generated_metadata(self):
        with tempfile.TemporaryDirectory() as a_dir, tempfile.TemporaryDirectory() as b_dir:
            a = pathlib.Path(a_dir)
            b = pathlib.Path(b_dir)
            for root in (a, b):
                (root / "lib").mkdir()
                (root / "lib" / "libdemo.a").write_bytes(b"same-payload")
            (a / "conanmanifest.txt").write_text("timestamp-a", encoding="utf-8")
            (b / "conanmanifest.txt").write_text("timestamp-b", encoding="utf-8")
            (a / "conaninfo.txt").write_text("info-a", encoding="utf-8")
            (b / "conaninfo.txt").write_text("info-b", encoding="utf-8")

            self.assertEqual(
                assurance._package_payload_digest(a),
                assurance._package_payload_digest(b),
            )
            self.assertNotEqual(
                assurance._package_tree_digest(a),
                assurance._package_tree_digest(b),
            )

    def test_receipt_binds_graph_source_and_package_digests(self):
        source_sha = "1" * 64
        package_sha = "2" * 64
        graph = {
            "nodes": {
                "1": {
                    "ref": "demo/1.0#rrev",
                    "name": "demo",
                    "version": "1.0",
                    "rrev": "rrev",
                    "package_id": "pkgid",
                    "prev": "prev",
                    "context": "host",
                    "settings": {"os": "Linux"},
                    "options": {"shared": "False"},
                }
            }
        }
        evidence = [
            assurance.Evidence(
                "demo/1.0",
                "source-artifact-bytes",
                "PASS",
                "verified",
                (f"sha256:{source_sha}",),
            ),
            assurance.Evidence(
                "demo/1.0",
                "package-bytes",
                "PASS",
                "verified",
                (f"sha256:{package_sha}",),
            ),
        ]

        identity = assurance.graph_identity(graph)
        packages = assurance._receipt_packages(identity, evidence)

        self.assertEqual(packages[0]["recipe_revision"], "rrev")
        self.assertEqual(packages[0]["package_id"], "pkgid")
        self.assertEqual(packages[0]["package_revision"], "prev")
        self.assertEqual(packages[0]["source_artifact_sha256"], source_sha)
        self.assertEqual(packages[0]["package_tree_sha256"], package_sha)

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
