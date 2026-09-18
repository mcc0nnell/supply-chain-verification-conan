import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

MODULE = pathlib.Path(__file__).parents[1] / "extensions" / "commands" / "cmd_assurance.py"
SPEC = importlib.util.spec_from_file_location("cmd_assurance", MODULE)
assurance = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = assurance
SPEC.loader.exec_module(assurance)


def _write_celix_bundle(
    path,
    *,
    symbolic="example.bundle",
    version="1.2.3",
    activator="libexample.so",
    private_libraries=(),
    extra_members=None,
    timestamp=(2026, 1, 1, 0, 0, 0),
    reverse=False,
):
    manifest = {
        "CELIX_BUNDLE_SYMBOLIC_NAME": symbolic,
        "CELIX_BUNDLE_VERSION": f"version<{version}>",
        "CELIX_BUNDLE_NAME": symbolic,
        "CELIX_BUNDLE_MANIFEST_VERSION": "version<2.0.0>",
    }
    if activator:
        manifest["CELIX_BUNDLE_ACTIVATOR_LIBRARY"] = activator
    if private_libraries:
        manifest["CELIX_BUNDLE_PRIVATE_LIBRARIES"] = list(private_libraries)

    members = [
        ("META-INF/MANIFEST.json", json.dumps(manifest, sort_keys=True).encode()),
    ]
    if activator:
        members.append((activator, b"activator-bytes"))
    for library in private_libraries:
        members.append((library, f"private:{library}".encode()))
    if extra_members:
        members.extend(extra_members)
    if reverse:
        members.reverse()

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members:
            info = zipfile.ZipInfo(name, date_time=timestamp)
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)


def _minimal_elf64_with_soname(soname: str) -> bytes:
    dynstr = b"\x00" + soname.encode("utf-8") + b"\x00"
    dynstr_offset = 64
    dynamic_offset = 96
    section_offset = 128
    total = section_offset + 3 * 64
    data = bytearray(total)

    data[:4] = b"\x7fELF"
    data[4] = 2  # ELFCLASS64
    data[5] = 1  # little endian
    data[6] = 1  # ELF version
    import struct
    struct.pack_into("<Q", data, 40, section_offset)
    struct.pack_into("<H", data, 52, 64)
    struct.pack_into("<H", data, 58, 64)
    struct.pack_into("<H", data, 60, 3)
    struct.pack_into("<H", data, 62, 0)

    data[dynstr_offset:dynstr_offset + len(dynstr)] = dynstr
    struct.pack_into("<qQ", data, dynamic_offset, 14, 1)
    struct.pack_into("<qQ", data, dynamic_offset + 16, 0, 0)

    dynstr_header = section_offset + 64
    struct.pack_into(
        "<IIQQQQIIQQ",
        data,
        dynstr_header,
        0, 3, 0, 0,
        dynstr_offset,
        len(dynstr),
        0, 0, 1, 0,
    )
    dynamic_header = section_offset + 128
    struct.pack_into(
        "<IIQQQQIIQQ",
        data,
        dynamic_header,
        0, 6, 0, 0,
        dynamic_offset,
        32,
        1, 0, 8, 16,
    )
    return bytes(data)


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

    def test_source_artifact_bytes_uses_matching_fallback_mirror(self):
        expected = "a" * 64
        node = {
            "name": "demo",
            "version": "1.0",
            "conandata": {
                "sources": {
                    "1.0": {
                        "url": [
                            "https://mirror-one.test/demo.tar.gz",
                            "https://mirror-two.test/demo.tar.gz",
                        ],
                        "sha256": expected,
                    }
                }
            },
        }
        with mock.patch.object(
            assurance,
            "_download_sha256",
            side_effect=[("b" * 64, 100), (expected, 100)],
        ):
            item = assurance._source_artifact_evidence(
                "demo/1.0",
                node,
                timeout=1,
                max_bytes=4096,
            )

        self.assertEqual(item.status, "PASS")
        self.assertIn("alternate mirror mismatch", item.summary)
        self.assertIn(f"sha256:{expected}", item.locations)

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

    def test_elf_soname_parser_reads_dynamic_soname(self):
        data = _minimal_elf64_with_soname("libcollision.so.1")
        self.assertEqual(
            assurance._elf_soname(data),
            "libcollision.so.1",
        )

    def test_celix_soname_collision_detects_divergent_runtime_libraries(self):
        first = assurance.CelixBundleRecord(
            path="/tmp/alpha.zip",
            symbolic_name="alpha.bundle",
            version="1.0.0",
            manifest_version="2.0.0",
            activator="libalpha.so",
            private_libraries=("libshared-a.so",),
            library_sonames=(("libshared-a.so", "libshared.so.1"),),
            archive_sha256="a" * 64,
            bundle_content_sha256="1" * 64,
            manifest_sha256="2" * 64,
            members=(("libshared-a.so", "3" * 64),),
        )
        second = assurance.CelixBundleRecord(
            path="/tmp/beta.zip",
            symbolic_name="beta.bundle",
            version="1.0.0",
            manifest_version="2.0.0",
            activator="libbeta.so",
            private_libraries=("libshared-b.so",),
            library_sonames=(("libshared-b.so", "libshared.so.1"),),
            archive_sha256="b" * 64,
            bundle_content_sha256="4" * 64,
            manifest_sha256="5" * 64,
            members=(("libshared-b.so", "6" * 64),),
        )

        collisions = assurance._celix_soname_collisions([first, second])

        self.assertEqual(len(collisions), 1)
        self.assertEqual(collisions[0]["soname"], "libshared.so.1")
        self.assertEqual(len(collisions[0]["libraries"]), 2)

    def test_celix_soname_collision_allows_identical_library_bytes(self):
        common_sha = "7" * 64
        first = assurance.CelixBundleRecord(
            path="/tmp/alpha.zip",
            symbolic_name="alpha.bundle",
            version="1.0.0",
            manifest_version="2.0.0",
            activator=None,
            private_libraries=("libshared-a.so",),
            library_sonames=(("libshared-a.so", "libshared.so.1"),),
            archive_sha256="a" * 64,
            bundle_content_sha256="1" * 64,
            manifest_sha256="2" * 64,
            members=(("libshared-a.so", common_sha),),
        )
        second = assurance.CelixBundleRecord(
            path="/tmp/beta.zip",
            symbolic_name="beta.bundle",
            version="1.0.0",
            manifest_version="2.0.0",
            activator=None,
            private_libraries=("libshared-b.so",),
            library_sonames=(("libshared-b.so", "libshared.so.1"),),
            archive_sha256="b" * 64,
            bundle_content_sha256="4" * 64,
            manifest_sha256="5" * 64,
            members=(("libshared-b.so", common_sha),),
        )

        self.assertEqual(
            assurance._celix_soname_collisions([first, second]),
            [],
        )

    def test_celix_container_fails_on_divergent_soname_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            config = root / "config.properties"
            config.write_text(
                "CELIX_AUTO_START_1=alpha.zip,beta.zip\n",
                encoding="utf-8",
            )

            alpha = assurance.CelixBundleRecord(
                path=str(root / "alpha.zip"),
                symbolic_name="alpha.bundle",
                version="1.0.0",
                manifest_version="2.0.0",
                activator=None,
                private_libraries=("libalpha.so",),
                library_sonames=(("libalpha.so", "libshared.so.1"),),
                archive_sha256="a" * 64,
                bundle_content_sha256="1" * 64,
                manifest_sha256="2" * 64,
                members=(("libalpha.so", "3" * 64),),
            )
            beta = assurance.CelixBundleRecord(
                path=str(root / "beta.zip"),
                symbolic_name="beta.bundle",
                version="1.0.0",
                manifest_version="2.0.0",
                activator=None,
                private_libraries=("libbeta.so",),
                library_sonames=(("libbeta.so", "libshared.so.1"),),
                archive_sha256="b" * 64,
                bundle_content_sha256="4" * 64,
                manifest_sha256="5" * 64,
                members=(("libbeta.so", "6" * 64),),
            )

            evidence, _ = assurance.inspect_celix_containers(
                [str(config)],
                [alpha, beta],
            )

        collision = next(
            item
            for item in evidence
            if item.check == "celix-runtime-library-collision"
        )
        self.assertEqual(collision.status, "FAIL")
        self.assertIn("SONAME collision", collision.summary)
        self.assertTrue(
            any("libshared.so.1" in location for location in collision.locations)
        )

    def test_celix_bundle_payload_is_stable_across_zip_order_and_timestamps(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first = root / "first.zip"
            second = root / "second.zip"
            _write_celix_bundle(
                first,
                private_libraries=("libprivate.so",),
                timestamp=(2026, 1, 1, 0, 0, 0),
            )
            _write_celix_bundle(
                second,
                private_libraries=("libprivate.so",),
                timestamp=(2026, 9, 18, 12, 0, 0),
                reverse=True,
            )

            first_record, first_evidence = assurance._inspect_celix_bundle(first)
            second_record, second_evidence = assurance._inspect_celix_bundle(second)

        self.assertEqual(
            first_record.bundle_content_sha256,
            second_record.bundle_content_sha256,
        )
        self.assertNotEqual(first_record.archive_sha256, second_record.archive_sha256)
        self.assertEqual(first_record.reference, "celix-bundle:example.bundle@1.2.3")
        self.assertTrue(all(item.status == "PASS" for item in first_evidence))
        self.assertTrue(all(item.status == "PASS" for item in second_evidence))

    def test_celix_bundle_content_matches_fineract_celix_v1_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "golden.zip"
            _write_celix_bundle(
                path,
                private_libraries=("libprivate.so",),
                extra_members=[("resources/config.json", b'{"mode":"demo"}')],
            )
            record, _ = assurance._inspect_celix_bundle(path)

        # Cross-checked against fineract-celix
        # fcr::sha256BundleContent (fcr.bundle-content.v1).
        self.assertEqual(
            record.bundle_content_sha256,
            "6e838b18b5a3bebddd3303547c41903b3e48b68d12fdd0dea7a51802b9859aed",
        )

    def test_celix_manifest_fails_when_declared_activator_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "broken.zip"
            manifest = {
                "CELIX_BUNDLE_SYMBOLIC_NAME": "broken.bundle",
                "CELIX_BUNDLE_VERSION": "version<1.0.0>",
                "CELIX_BUNDLE_MANIFEST_VERSION": "version<2.0.0>",
                "CELIX_BUNDLE_ACTIVATOR_LIBRARY": "libmissing.so",
            }
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(
                    "META-INF/MANIFEST.json",
                    json.dumps(manifest),
                )

            record, evidence = assurance._inspect_celix_bundle(path)

        closure_evidence = next(
            item for item in evidence if item.check == "celix-library-closure"
        )
        self.assertEqual(record.symbolic_name, "broken.bundle")
        self.assertEqual(closure_evidence.status, "FAIL")
        self.assertIn("libmissing.so", closure_evidence.summary)

    def test_celix_archive_layout_rejects_parent_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "unsafe.zip"
            _write_celix_bundle(
                path,
                extra_members=[("../escape.so", b"bad")],
            )

            _, evidence = assurance._inspect_celix_bundle(path)

        layout = next(
            item for item in evidence if item.check == "celix-archive-layout"
        )
        payload = next(
            item for item in evidence if item.check == "celix-bundle-content"
        )
        self.assertEqual(layout.status, "FAIL")
        self.assertEqual(payload.status, "FAIL")
        self.assertIn("unsafe bundle member path", layout.summary)

    def test_celix_container_composition_binds_start_level_and_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first_path = root / "alpha.zip"
            second_path = root / "beta.zip"
            _write_celix_bundle(
                first_path,
                symbolic="alpha.bundle",
                version="1.0.0",
                activator="libalpha.so",
            )
            _write_celix_bundle(
                second_path,
                symbolic="beta.bundle",
                version="2.0.0",
                activator="libbeta.so",
            )
            _, bundles = assurance.inspect_celix_bundles(
                [str(first_path), str(second_path)],
                [],
            )

            config = root / "config.properties"
            config.write_text(
                "CELIX_AUTO_START_1=alpha.zip,beta.zip\n"
                "CELIX_AUTO_INSTALL=beta.zip\n",
                encoding="utf-8",
            )
            evidence, records = assurance.inspect_celix_containers(
                [str(config)],
                bundles,
            )

        self.assertEqual(len(records), 1)
        self.assertEqual(evidence[0].status, "PASS")
        self.assertEqual(len(records[0].bundles), 3)
        self.assertEqual(records[0].bundles[0]["level"], 1)
        self.assertEqual(records[0].bundles[0]["order"], 0)
        self.assertEqual(records[0].bundles[0]["bundle"], "celix-bundle:alpha.bundle@1.0.0")
        self.assertEqual(records[0].bundles[1]["bundle"], "celix-bundle:beta.bundle@2.0.0")
        self.assertEqual(records[0].bundles[2]["mode"], "auto-install")
        self.assertEqual(len(records[0].composition_sha256), 64)

    def test_celix_generated_container_source_parses_embedded_json(self):
        source = """
#include <celix_launcher.h>
#define CELIX_MULTI_LINE_STRING(...) #__VA_ARGS__

int main(int argc, char *argv[]) {
    const char * config = CELIX_MULTI_LINE_STRING(
{
    "CELIX_AUTO_START_1":"alpha.zip,beta.zip",
    "CELIX_BUNDLES_PATH":"bundles",
    "CELIX_CONTAINER_NAME":"AssuranceContainer"
});
    return celix_launcher_launchAndWait(argc, argv, config);
}
"""
        config = assurance._extract_celix_embedded_json(source)
        self.assertEqual(
            config["CELIX_AUTO_START_1"],
            "alpha.zip,beta.zip",
        )
        self.assertEqual(config["CELIX_BUNDLES_PATH"], "bundles")
        self.assertEqual(config["CELIX_CONTAINER_NAME"], "AssuranceContainer")

    def test_celix_generated_container_source_handles_braces_in_strings(self):
        source = r'''
const char * config = CELIX_MULTI_LINE_STRING(
{
    "CELIX_AUTO_START_3":"alpha.zip",
    "custom":"literal { braces } and \"quote\""
});
'''
        config = assurance._extract_celix_embedded_json(source)
        self.assertEqual(config["CELIX_AUTO_START_3"], "alpha.zip")
        self.assertEqual(config["custom"], 'literal { braces } and "quote"')

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
