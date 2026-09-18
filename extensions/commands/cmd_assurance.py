"""Conan supply-chain assurance custom command."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from conan.api.model.refs import PkgReference
from conan.api.output import ConanOutput, cli_out_write
from conan.cli.command import conan_command
from conan.errors import ConanException


SCORECARD_API = "https://api.scorecard.dev/projects/"
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class Evidence:
    reference: str
    check: str
    status: str
    summary: str
    locations: tuple[str, ...] = ()

    def json(self) -> dict:
        value = asdict(self)
        value["locations"] = list(self.locations)
        return value


@dataclass(frozen=True)
class RebuildRecord:
    reference: str
    recipe_revision: str
    consumed_package_id: str
    consumed_package_revision: str
    consumed_payload_sha256: str
    rebuild_payload_sha256: tuple[str, ...]
    rebuild_package_revisions: tuple[str, ...]
    rebuild_log_sha256: tuple[str, ...]
    repeatable: bool
    matches_consumed: bool
    builder: dict


@dataclass(frozen=True)
class CelixBundleRecord:
    path: str
    symbolic_name: str
    version: str
    manifest_version: str
    activator: str | None
    private_libraries: tuple[str, ...]
    library_sonames: tuple[tuple[str, str], ...]
    archive_sha256: str
    bundle_content_sha256: str
    manifest_sha256: str
    members: tuple[tuple[str, str], ...]

    @property
    def reference(self) -> str:
        return f"celix-bundle:{self.symbolic_name}@{self.version}"

    def json(self) -> dict:
        return {
            "path": self.path,
            "reference": self.reference,
            "symbolic_name": self.symbolic_name,
            "version": self.version,
            "manifest_version": self.manifest_version,
            "activator": self.activator,
            "private_libraries": list(self.private_libraries),
            "library_sonames": [
                {"path": path, "soname": soname}
                for path, soname in self.library_sonames
            ],
            "archive_sha256": self.archive_sha256,
            "bundle_content_sha256": self.bundle_content_sha256,
            "manifest_sha256": self.manifest_sha256,
            "members": [
                {"path": path, "sha256": digest}
                for path, digest in self.members
            ],
        }


@dataclass(frozen=True)
class CelixContainerRecord:
    path: str
    config_sha256: str
    composition_sha256: str
    bundles: tuple[dict, ...]

    @property
    def reference(self) -> str:
        return f"celix-container:{self.path}"

    def json(self) -> dict:
        return {
            "path": self.path,
            "reference": self.reference,
            "config_sha256": self.config_sha256,
            "composition_sha256": self.composition_sha256,
            "bundles": list(self.bundles),
        }


def _format_json(result):
    cli_out_write(json.dumps(result, indent=2, sort_keys=True))


def _format_ndjson(result):
    for item in result["evidence"]:
        cli_out_write(json.dumps(item, sort_keys=True))


@conan_command(
    group="Security",
    formatters={"json": _format_json, "ndjson": _format_ndjson},
)
def assurance(conan_api, parser, *args):
    """Verify supply-chain evidence for a resolved Conan dependency graph."""
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Consumer recipe path; ignored when --requires/--tool-requires is used",
    )
    parser.add_argument(
        "--requires",
        action="append",
        default=[],
        help="Resolve a requirement directly (repeatable)",
    )
    parser.add_argument(
        "--tool-requires",
        action="append",
        default=[],
        help="Resolve a tool requirement directly (repeatable)",
    )
    parser.add_argument(
        "-r",
        "--remote",
        default="conancenter",
        help="Remote passed to conan graph info (default: conancenter)",
    )
    parser.add_argument(
        "--graph-arg",
        action="append",
        default=[],
        help="Extra argument passed verbatim to conan graph info (repeatable)",
    )
    parser.add_argument(
        "--minimum-scorecard-score",
        type=float,
        default=-1.0,
        help="Fail a published OpenSSF Scorecard below this value; negative disables threshold",
    )
    parser.add_argument(
        "--scorecard-timeout",
        type=float,
        default=5.0,
        help="OpenSSF Scorecard HTTP timeout in seconds",
    )
    parser.add_argument(
        "--skip-scorecard",
        action="store_true",
        help="Do not perform OpenSSF Scorecard network lookups",
    )
    parser.add_argument(
        "--verify-source-bytes",
        action="store_true",
        help="Download source archives and recompute declared SHA-256 digests",
    )
    parser.add_argument(
        "--source-timeout",
        type=float,
        default=30.0,
        help="Source artifact HTTP timeout in seconds",
    )
    parser.add_argument(
        "--source-max-bytes",
        type=int,
        default=268435456,
        help="Maximum bytes downloaded per source artifact (default: 256 MiB)",
    )
    parser.add_argument(
        "--materialize-packages",
        action="store_true",
        help="Run conan install first so resolved package bytes are present in the local cache",
    )
    parser.add_argument(
        "--verify-package-bytes",
        action="store_true",
        help="Hash cached package file trees and bind them to package ID/revision",
    )
    parser.add_argument(
        "--rebuild-package",
        action="append",
        default=[],
        help="Rebuild this resolved name/version in clean Conan homes (repeatable)",
    )
    parser.add_argument(
        "--rebuild-count",
        type=int,
        default=2,
        help="Number of independent clean-cache rebuilds (default: 2)",
    )
    parser.add_argument(
        "--rebuild-timeout",
        type=int,
        default=900,
        help="Timeout for each clean rebuild in seconds (default: 900)",
    )
    parser.add_argument(
        "--celix-bundle",
        action="append",
        default=[],
        help="Inspect a Celix bundle ZIP as a first-class assurance subject (repeatable)",
    )
    parser.add_argument(
        "--celix-bundle-dir",
        action="append",
        default=[],
        help="Discover Celix bundle ZIPs recursively under this directory (repeatable)",
    )
    parser.add_argument(
        "--celix-container-config",
        action="append",
        default=[],
        help="Bind a Celix JSON or .properties container config to verified bundle identities (repeatable)",
    )
    parser.add_argument(
        "--report",
        help="Write deterministic NDJSON evidence to this path before policy enforcement",
    )
    parser.add_argument(
        "--receipt",
        help="Write a deterministic JSON receipt binding graph identity and evidence digests",
    )
    parser.add_argument(
        "--provenance",
        help="Write a custom in-toto predicate for clean rebuild evidence",
    )
    parser.add_argument(
        "--celix-provenance",
        help="Write a custom predicate for Celix bundle identities and container composition",
    )
    parser.add_argument(
        "--celix-only",
        action="store_true",
        help="Inspect Celix runtime artifacts without resolving a Conan dependency graph",
    )
    parser.add_argument(
        "--fail-on-failure",
        action="store_true",
        help="Return non-zero when any check returns FAIL",
    )
    parser.add_argument(
        "--fail-on-unknown",
        action="store_true",
        help="Return non-zero when any check returns UNKNOWN",
    )
    parsed = parser.parse_args(*args)

    if parsed.scorecard_timeout <= 0:
        raise ConanException("--scorecard-timeout must be positive")
    if parsed.source_timeout <= 0:
        raise ConanException("--source-timeout must be positive")
    if parsed.source_max_bytes <= 0:
        raise ConanException("--source-max-bytes must be positive")
    if parsed.rebuild_timeout <= 0:
        raise ConanException("--rebuild-timeout must be positive")
    if parsed.rebuild_package and parsed.rebuild_count < 2:
        raise ConanException(
            "--rebuild-count must be at least 2 when reproducibility is checked"
        )
    if parsed.provenance and not parsed.rebuild_package:
        raise ConanException("--provenance requires at least one --rebuild-package")
    if parsed.celix_provenance and not (
        parsed.celix_bundle or parsed.celix_bundle_dir
    ):
        raise ConanException(
            "--celix-provenance requires --celix-bundle or --celix-bundle-dir"
        )
    if parsed.celix_only and not (
        parsed.celix_bundle
        or parsed.celix_bundle_dir
        or parsed.celix_container_config
    ):
        raise ConanException(
            "--celix-only requires Celix bundle or container input"
        )
    if parsed.celix_only and (
        parsed.requires
        or parsed.tool_requires
        or parsed.rebuild_package
        or parsed.materialize_packages
        or parsed.verify_package_bytes
        or parsed.verify_source_bytes
    ):
        raise ConanException(
            "--celix-only cannot be combined with Conan graph/build verification options"
        )
    if parsed.rebuild_package:
        parsed.materialize_packages = True
        parsed.verify_package_bytes = True
        parsed.verify_source_bytes = True
    if parsed.verify_package_bytes and not parsed.materialize_packages:
        raise ConanException(
            "--verify-package-bytes requires --materialize-packages "
            "so package bytes are present in the Conan cache"
        )

    serialized = {"nodes": {}}
    evidence: list[Evidence] = []

    if not parsed.celix_only:
        if parsed.materialize_packages:
            with tempfile.TemporaryDirectory(prefix="conan-assurance-") as output_folder:
                install_result = conan_api.command.run(
                    _install_command(parsed, output_folder)
                )
            if install_result.get("conan_error"):
                raise ConanException(install_result["conan_error"])

        graph_result = conan_api.command.run(_graph_command(parsed))
        if graph_result.get("conan_error"):
            raise ConanException(graph_result["conan_error"])

        serialized = graph_result["graph"].serialize()
        evidence = inspect_graph(
            serialized,
            conan_api=conan_api,
            minimum_scorecard_score=parsed.minimum_scorecard_score,
            scorecard_timeout=parsed.scorecard_timeout,
            skip_scorecard=parsed.skip_scorecard,
            verify_source_bytes=parsed.verify_source_bytes,
            source_timeout=parsed.source_timeout,
            source_max_bytes=parsed.source_max_bytes,
            verify_package_bytes=parsed.verify_package_bytes,
        )
    rebuild_records = []
    if parsed.rebuild_package:
        rebuild_evidence, rebuild_records = verify_reproducible_builds(
            serialized,
            conan_api,
            targets=parsed.rebuild_package,
            count=parsed.rebuild_count,
            timeout=parsed.rebuild_timeout,
            remote=parsed.remote,
            graph_args=parsed.graph_arg,
        )
        evidence.extend(rebuild_evidence)

    celix_bundles: list[CelixBundleRecord] = []
    celix_containers: list[CelixContainerRecord] = []
    if parsed.celix_bundle or parsed.celix_bundle_dir:
        celix_evidence, celix_bundles = inspect_celix_bundles(
            parsed.celix_bundle,
            parsed.celix_bundle_dir,
        )
        evidence.extend(celix_evidence)

    if parsed.celix_container_config:
        container_evidence, celix_containers = inspect_celix_containers(
            parsed.celix_container_config,
            celix_bundles,
        )
        evidence.extend(container_evidence)

    evidence.sort(key=lambda item: (item.reference, item.check))
    result = summarize(evidence)

    if parsed.report:
        write_ndjson(parsed.report, evidence)
    if parsed.receipt:
        write_receipt(
            parsed.receipt,
            serialized,
            evidence,
            celix_bundles=celix_bundles,
            celix_containers=celix_containers,
        )
    if parsed.provenance:
        write_provenance(parsed.provenance, serialized, evidence, rebuild_records)
    if parsed.celix_provenance:
        write_celix_provenance(
            parsed.celix_provenance,
            celix_bundles,
            celix_containers,
            evidence,
        )

    _print_text(result)
    _enforce_policy(
        result,
        fail_on_failure=parsed.fail_on_failure,
        fail_on_unknown=parsed.fail_on_unknown,
    )
    return result


def _graph_command(parsed) -> list[str]:
    command = ["graph", "info"]
    if parsed.requires or parsed.tool_requires:
        for value in parsed.requires:
            command.append(f"--requires={value}")
        for value in parsed.tool_requires:
            command.append(f"--tool-requires={value}")
    else:
        command.append(parsed.path)

    if parsed.remote:
        command.append(f"-r={parsed.remote}")
    command.extend(parsed.graph_arg)
    return command


def _install_command(parsed, output_folder: str) -> list[str]:
    command = ["install"]
    if parsed.requires or parsed.tool_requires:
        for value in parsed.requires:
            command.append(f"--requires={value}")
        for value in parsed.tool_requires:
            command.append(f"--tool-requires={value}")
    else:
        command.append(parsed.path)

    if parsed.remote:
        command.append(f"-r={parsed.remote}")
    command.extend(parsed.graph_arg)
    command.append(f"--output-folder={output_folder}")
    return command


def inspect_graph(
    serialized_graph: dict,
    *,
    conan_api=None,
    minimum_scorecard_score: float = -1.0,
    scorecard_timeout: float = 5.0,
    skip_scorecard: bool = False,
    verify_source_bytes: bool = False,
    source_timeout: float = 30.0,
    source_max_bytes: int = 268435456,
    verify_package_bytes: bool = False,
) -> list[Evidence]:
    evidence: list[Evidence] = []
    nodes = serialized_graph.get("nodes", {})

    for _, node in sorted(nodes.items(), key=lambda item: str(item[0])):
        reference = _reference(node)
        if reference is None:
            continue

        evidence.append(_recipe_revision_evidence(reference, node))
        evidence.append(_source_digest_evidence(reference, node))

        if verify_source_bytes:
            evidence.append(
                _source_artifact_evidence(
                    reference,
                    node,
                    timeout=source_timeout,
                    max_bytes=source_max_bytes,
                )
            )

        if verify_package_bytes:
            evidence.append(
                _package_bytes_evidence(reference, node, conan_api)
            )

        if skip_scorecard:
            evidence.append(
                Evidence(
                    reference,
                    "openssf-scorecard",
                    "UNKNOWN",
                    "OpenSSF Scorecard lookup skipped",
                )
            )
        else:
            evidence.append(
                _scorecard_evidence(
                    reference,
                    node,
                    minimum_score=minimum_scorecard_score,
                    timeout=scorecard_timeout,
                )
            )

    return sorted(evidence, key=lambda e: (e.reference, e.check))


def _reference(node: dict) -> str | None:
    ref = node.get("ref")
    name = node.get("name")
    version = node.get("version")
    if not name or not version or not ref or ref == "conanfile":
        return None
    return f"{name}/{version}"


def _recipe_revision_evidence(reference: str, node: dict) -> Evidence:
    revision = node.get("rrev")
    if revision:
        return Evidence(
            reference,
            "recipe-revision",
            "PASS",
            f"resolved recipe revision {revision}",
            (f"conan:{node.get('ref')}",),
        )
    return Evidence(
        reference,
        "recipe-revision",
        "UNKNOWN",
        "resolved graph does not expose a recipe revision",
    )


def _source_digest_evidence(reference: str, node: dict) -> Evidence:
    entries = source_entries(node)
    if not entries:
        return Evidence(
            reference,
            "source-digest",
            "UNKNOWN",
            "recipe does not expose version-matched conandata source metadata",
        )

    urls: list[str] = []
    digests: list[str] = []
    missing_digest = False

    for entry in entries:
        entry_urls = _as_strings(entry.get("url"))
        if not entry_urls:
            continue
        urls.extend(entry_urls)

        digest = entry.get("sha256")
        if isinstance(digest, str) and SHA256_RE.fullmatch(digest.strip()):
            digests.append(digest.lower())
        else:
            missing_digest = True

    if not urls:
        return Evidence(
            reference,
            "source-digest",
            "UNKNOWN",
            "source metadata does not contain a URL",
        )

    if missing_digest or not digests:
        return Evidence(
            reference,
            "source-digest",
            "FAIL",
            "one or more published source locations are not pinned by SHA-256",
            tuple(sorted(set(urls))),
        )

    unique = sorted(set(digests))
    return Evidence(
        reference,
        "source-digest",
        "PASS",
        "published source archive is pinned by SHA-256"
        if len(unique) == 1
        else f"published source archives are pinned by {len(unique)} SHA-256 digests",
        tuple(sorted(set(urls))),
    )


def _source_artifact_evidence(
    reference: str,
    node: dict,
    *,
    timeout: float,
    max_bytes: int,
) -> Evidence:
    entries = source_entries(node)
    if not entries:
        return Evidence(
            reference,
            "source-artifact-bytes",
            "UNKNOWN",
            "recipe does not expose version-matched source metadata",
        )

    verified_locations: list[str] = []
    verified_count = 0
    mismatch_count = 0

    for entry in entries:
        digest = entry.get("sha256")
        urls = _as_strings(entry.get("url"))
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest.strip()):
            return Evidence(
                reference,
                "source-artifact-bytes",
                "UNKNOWN",
                "source bytes cannot be verified without a declared SHA-256",
                tuple(urls),
            )
        if not urls:
            return Evidence(
                reference,
                "source-artifact-bytes",
                "UNKNOWN",
                "source bytes cannot be verified without a source URL",
            )

        expected = digest.lower()
        last_problem = "all source mirrors were unavailable"
        entry_mismatches = 0

        for url in urls:
            try:
                actual, size = _download_sha256(
                    url,
                    timeout=timeout,
                    max_bytes=max_bytes,
                )
            except urllib.error.HTTPError as exc:
                last_problem = f"source mirror returned HTTP {exc.code}"
                continue
            except _ArtifactTooLarge:
                return Evidence(
                    reference,
                    "source-artifact-bytes",
                    "UNKNOWN",
                    f"source artifact exceeds configured limit of {max_bytes} bytes",
                    (url, f"sha256:{expected}"),
                )
            except (urllib.error.URLError, TimeoutError, OSError):
                last_problem = "source mirror lookup was not conclusive"
                continue

            if actual != expected:
                mismatch_count += 1
                entry_mismatches += 1
                verified_locations.extend(
                    [url, f"mismatch-sha256:{actual}"]
                )
                last_problem = (
                    "source SHA-256 mismatch at every available mirror"
                )
                continue

            verified_count += 1
            verified_locations.extend(
                [url, f"sha256:{actual}", f"bytes:{size}"]
            )
            break
        else:
            return Evidence(
                reference,
                "source-artifact-bytes",
                "FAIL" if entry_mismatches else "UNKNOWN",
                last_problem,
                tuple(verified_locations + urls + [f"sha256:{expected}"]),
            )

    if mismatch_count:
        summary = (
            "downloaded source bytes match declared SHA-256; "
            f"{mismatch_count} alternate mirror mismatch(es) were rejected"
        )
    elif verified_count == 1:
        summary = "downloaded source bytes match declared SHA-256"
    else:
        summary = (
            f"{verified_count} downloaded source artifacts "
            "match declared SHA-256"
        )

    return Evidence(
        reference,
        "source-artifact-bytes",
        "PASS",
        summary,
        tuple(verified_locations),
    )


class _ArtifactTooLarge(Exception):
    pass


def _download_sha256(
    url: str,
    *,
    timeout: float,
    max_bytes: int,
) -> tuple[str, int]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "supply-chain-verification-conan/0.2"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        length = response.headers.get("Content-Length")
        if length:
            try:
                if int(length) > max_bytes:
                    raise _ArtifactTooLarge()
            except ValueError:
                pass

        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise _ArtifactTooLarge()
            digest.update(chunk)

    return digest.hexdigest(), total


def _package_bytes_evidence(reference: str, node: dict, conan_api) -> Evidence:
    if conan_api is None:
        return Evidence(
            reference,
            "package-bytes",
            "UNKNOWN",
            "Conan cache API is unavailable",
        )

    rrev = node.get("rrev")
    package_id = node.get("package_id")
    prev = node.get("prev")
    ref = node.get("ref")
    if not ref or not rrev or not package_id or not prev:
        return Evidence(
            reference,
            "package-bytes",
            "UNKNOWN",
            "resolved graph does not expose complete package identity",
        )

    recipe_ref = str(ref).split("#", 1)[0]
    fullref = f"{recipe_ref}#{rrev}:{package_id}#{prev}"

    try:
        package_path = Path(
            conan_api.cache.package_path(PkgReference.loads(fullref))
        )
    except Exception:
        return Evidence(
            reference,
            "package-bytes",
            "UNKNOWN",
            "resolved package could not be located in the Conan cache",
            (f"conan:{fullref}",),
        )

    if not package_path.is_dir():
        return Evidence(
            reference,
            "package-bytes",
            "UNKNOWN",
            "resolved package bytes are not materialized in the Conan cache",
            (f"conan:{fullref}",),
        )

    digest, files, total = _package_tree_digest(package_path)
    return Evidence(
        reference,
        "package-bytes",
        "PASS",
        (
            f"cached package tree sha256 {digest}; "
            f"files={files} bytes={total} "
            f"package_id={package_id} package_revision={prev}"
        ),
        (f"conan:{fullref}", f"sha256:{digest}"),
    )


def _package_tree_digest(root: Path) -> tuple[str, int, int]:
    return _digest_tree(root, excluded=frozenset())


def _package_payload_digest(root: Path) -> tuple[str, int, int]:
    return _digest_tree(
        root,
        excluded=frozenset({"conaninfo.txt", "conanmanifest.txt"}),
    )


def _digest_tree(
    root: Path,
    *,
    excluded: frozenset[str],
) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    files = 0
    total = 0

    for path in sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative in excluded:
            continue
        if path.is_symlink():
            target = os.readlink(path)
            digest.update(b"L\0")
            digest.update(relative.encode("utf-8"))
            digest.update(b"\0")
            digest.update(target.encode("utf-8"))
            digest.update(b"\0")
            continue
        if not path.is_file():
            continue

        stat = path.stat()
        size = stat.st_size
        mode = stat.st_mode & 0o777
        files += 1
        total += size
        digest.update(b"F\0")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(oct(mode).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")

        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)

    return digest.hexdigest(), files, total

def verify_reproducible_builds(
    serialized_graph: dict,
    conan_api,
    *,
    targets: list[str],
    count: int,
    timeout: int,
    remote: str,
    graph_args: list[str],
) -> tuple[list[Evidence], list[RebuildRecord]]:
    nodes = {
        _reference(node): node
        for node in serialized_graph.get("nodes", {}).values()
        if _reference(node) is not None
    }
    evidence: list[Evidence] = []
    records: list[RebuildRecord] = []

    for target in targets:
        node = nodes.get(target)
        if node is None:
            evidence.append(Evidence(
                target, "rebuild-repeatability", "UNKNOWN",
                "requested rebuild target is not present in the resolved graph",
            ))
            continue
        try:
            target_path, fullref = _resolved_package_path(conan_api, node)
            consumed_sha, _, _ = _package_payload_digest(target_path)
        except Exception:
            evidence.append(Evidence(
                target, "rebuild-repeatability", "UNKNOWN",
                "consumed package payload could not be read from the Conan cache",
            ))
            continue

        attempts: list[dict] = []
        for attempt in range(1, count + 1):
            try:
                attempts.append(_clean_rebuild(
                    target, node, conan_api,
                    remote=remote,
                    graph_args=graph_args,
                    timeout=timeout,
                    attempt=attempt,
                ))
            except Exception as exc:
                evidence.append(Evidence(
                    target, "rebuild-repeatability", "UNKNOWN",
                    f"clean rebuild {attempt} failed: {type(exc).__name__}",
                    (f"conan:{fullref}",),
                ))
                attempts = []
                break
        if not attempts:
            continue
        rebuild_digests = tuple(item["payload_sha256"] for item in attempts)
        rebuild_prevs = tuple(item["package_revision"] for item in attempts)
        log_digests = tuple(item["log_sha256"] for item in attempts)
        repeatable = len(set(rebuild_digests)) == 1
        matches_consumed = repeatable and rebuild_digests[0] == consumed_sha
        locations = (
            f"conan:{fullref}",
            f"sha256:{consumed_sha}",
            *tuple(
                f"rebuild:{i + 1}:sha256:{digest}"
                for i, digest in enumerate(rebuild_digests)
            ),
        )

        evidence.append(Evidence(
            target,
            "rebuild-repeatability",
            "PASS" if repeatable else "FAIL",
            (
                f"{count} clean-cache rebuilds produced the same package payload"
                if repeatable else
                f"{count} clean-cache rebuilds produced different package payloads"
            ),
            locations,
        ))
        evidence.append(Evidence(
            target,
            "consumed-binary-reproduction",
            "PASS" if matches_consumed else "FAIL",
            (
                "clean rebuild payload matches the package bytes Conan consumed"
                if matches_consumed else
                "clean rebuilds are repeatable but do not match the package bytes Conan consumed"
                if repeatable else
                "clean rebuilds are not repeatable, so consumed binary reproduction is unproven"
            ),
            locations,
        ))

        records.append(RebuildRecord(
            reference=target,
            recipe_revision=str(node.get("rrev")),
            consumed_package_id=str(node.get("package_id")),
            consumed_package_revision=str(node.get("prev")),
            consumed_payload_sha256=consumed_sha,
            rebuild_payload_sha256=rebuild_digests,
            rebuild_package_revisions=rebuild_prevs,
            rebuild_log_sha256=log_digests,
            repeatable=repeatable,
            matches_consumed=matches_consumed,
            builder=_builder_identity(),
        ))

    return evidence, records
def _resolved_package_path(conan_api, node: dict) -> tuple[Path, str]:
    ref = str(node["ref"]).split("#", 1)[0]
    fullref = (
        f"{ref}#{node['rrev']}:{node['package_id']}#{node['prev']}"
    )
    return Path(
        conan_api.cache.package_path(PkgReference.loads(fullref))
    ), fullref


def _clean_rebuild(
    reference: str,
    node: dict,
    conan_api,
    *,
    remote: str,
    graph_args: list[str],
    timeout: int,
    attempt: int,
) -> dict:
    conan = shutil.which("conan")
    if conan is None:
        raise RuntimeError("conan executable not found")

    recipe_ref = str(node["ref"]).split("#", 1)[0]
    exact_ref = f"{recipe_ref}#{node['rrev']}"
    build_pattern = f"{node['name']}/*"
    with tempfile.TemporaryDirectory(
        prefix=f"conan-assurance-rebuild-{attempt}-"
    ) as directory:
        root = Path(directory)
        home = root / "home"
        output = root / "out"
        _copy_conan_rebuild_config(Path(conan_api.home_folder), home)
        env = os.environ.copy()
        env["CONAN_HOME"] = str(home)

        command = [
            conan, "install", f"--requires={exact_ref}",
            f"-r={remote}", f"--build={build_pattern}",
            f"--output-folder={output}", *graph_args,
        ]
        completed = subprocess.run(
            command, env=env, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
        log = completed.stdout + completed.stderr
        if completed.returncode != 0:
            raise RuntimeError(
                f"conan rebuild exited {completed.returncode}: {log[-1000:]}"
            )

        graph_cmd = [
            conan, "graph", "info", f"--requires={exact_ref}",
            f"-r={remote}", *graph_args, "--format=json",
        ]
        graph = subprocess.run(
            graph_cmd, env=env, capture_output=True, text=True,
            timeout=timeout, check=True,
        )
        rebuilt = _find_rebuilt_node(json.loads(graph.stdout), reference)
        rebuilt_ref = str(rebuilt["ref"]).split("#", 1)[0]
        fullref = (
            f"{rebuilt_ref}#{rebuilt['rrev']}:"
            f"{rebuilt['package_id']}#{rebuilt['prev']}"
        )
        cache_path = subprocess.run(
            [conan, "cache", "path", fullref],
            env=env, capture_output=True, text=True,
            timeout=60, check=True,
        ).stdout.strip().splitlines()[-1]
        payload_sha, files, size = _package_payload_digest(Path(cache_path))

        return {
            "payload_sha256": payload_sha,
            "files": files,
            "bytes": size,
            "package_id": str(rebuilt["package_id"]),
            "package_revision": str(rebuilt["prev"]),
            "log_sha256": hashlib.sha256(log.encode("utf-8")).hexdigest(),
        }


def _find_rebuilt_node(graph: dict, reference: str) -> dict:
    for node in graph.get("graph", {}).get("nodes", {}).values():
        if _reference(node) == reference:
            return node
    raise RuntimeError(f"rebuilt node {reference} not found")
def _copy_conan_rebuild_config(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    profiles = source / "profiles"
    if profiles.is_dir():
        shutil.copytree(profiles, destination / "profiles", dirs_exist_ok=True)

    for name in ("global.conf", "settings.yml", "settings_user.yml"):
        path = source / name
        if path.is_file():
            shutil.copy2(path, destination / name)


def _builder_identity() -> dict:
    identity = {
        "platform": os.uname().sysname + "-" + os.uname().machine,
    }
    for name, command in (
        ("conan", ["conan", "--version"]),
        ("compiler", ["cc", "--version"]),
        ("cmake", ["cmake", "--version"]),
    ):
        try:
            result = subprocess.run(
                command, capture_output=True, text=True,
                timeout=10, check=False,
            )
            first = (result.stdout or result.stderr).splitlines()
            identity[name] = first[0] if first else "unknown"
        except (OSError, subprocess.SubprocessError):
            identity[name] = "unavailable"
    return identity


def source_entries(node: dict) -> list[dict]:
    conandata = node.get("conandata")
    version = node.get("version")
    if not isinstance(conandata, dict) or not version:
        return []

    sources = conandata.get("sources")
    if not isinstance(sources, dict):
        return []

    value = sources.get(str(version))
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [entry for entry in value if isinstance(entry, dict)]
    return []


def _scorecard_evidence(
    reference: str,
    node: dict,
    *,
    minimum_score: float,
    timeout: float,
) -> Evidence:
    locations = upstream_locations(node)
    project = resolve_github_project(locations)
    if project is None:
        return Evidence(
            reference,
            "openssf-scorecard",
            "UNKNOWN",
            "no supported canonical GitHub source repository found in recipe source metadata",
            tuple(locations),
        )

    endpoint = SCORECARD_API + project
    evidence_locations = tuple(locations + [f"https://{project}", endpoint])

    request = urllib.request.Request(
        endpoint,
        headers={
            "Accept": "application/json",
            "User-Agent": "supply-chain-verification-conan/0.1",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.status
            body = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 410):
            return Evidence(
                reference,
                "openssf-scorecard",
                "FAIL",
                "OpenSSF Scorecard result is not published",
                evidence_locations,
            )
        return Evidence(
            reference,
            "openssf-scorecard",
            "UNKNOWN",
            f"OpenSSF Scorecard lookup returned HTTP {exc.code}",
            evidence_locations,
        )
    except (urllib.error.URLError, TimeoutError, OSError):
        return Evidence(
            reference,
            "openssf-scorecard",
            "UNKNOWN",
            "OpenSSF Scorecard lookup was not conclusive",
            evidence_locations,
        )

    if status < 200 or status >= 300:
        return Evidence(
            reference,
            "openssf-scorecard",
            "UNKNOWN",
            f"OpenSSF Scorecard lookup returned HTTP {status}",
            evidence_locations,
        )

    try:
        payload = json.loads(body)
        score = float(payload["score"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return Evidence(
            reference,
            "openssf-scorecard",
            "UNKNOWN",
            "OpenSSF Scorecard response did not contain a numeric score",
            evidence_locations,
        )

    date = payload.get("date")
    detail = f"OpenSSF Scorecard {_format_score(score)}"
    if isinstance(date, str) and date:
        detail += f" ({date})"

    if minimum_score >= 0 and score < minimum_score:
        return Evidence(
            reference,
            "openssf-scorecard",
            "FAIL",
            f"{detail} is below required minimum {_format_score(minimum_score)}",
            evidence_locations,
        )

    return Evidence(
        reference,
        "openssf-scorecard",
        "PASS",
        detail,
        evidence_locations,
    )


def upstream_locations(node: dict) -> list[str]:
    values: list[str] = []
    for entry in source_entries(node):
        values.extend(_as_strings(entry.get("url")))

    homepage = node.get("homepage")
    if isinstance(homepage, str) and homepage.strip():
        values.append(homepage.strip())

    # Conan Center recipe URLs usually identify the recipe index, not upstream.
    # Only consider node["url"] when there is no source/homepage metadata.
    if not values:
        recipe_url = node.get("url")
        if isinstance(recipe_url, str) and recipe_url.strip():
            values.append(recipe_url.strip())

    return list(dict.fromkeys(values))


def resolve_github_project(locations: Iterable[str]) -> str | None:
    for value in locations:
        project = canonical_github_project(value)
        if project:
            return project
    return None


def canonical_github_project(value: str) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None

    candidate = value.strip()
    if candidate.startswith("git@github.com:"):
        candidate = "https://github.com/" + candidate[len("git@github.com:"):]
    elif candidate.startswith("git://github.com/"):
        candidate = "https://github.com/" + candidate[len("git://github.com/"):]

    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None

    host = (parsed.hostname or "").lower()
    parts = [part for part in parsed.path.split("/") if part]

    if host == "github.com" and len(parts) >= 2:
        owner, repo = parts[0], parts[1]
    elif host == "codeload.github.com" and len(parts) >= 2:
        owner, repo = parts[0], parts[1]
    elif host == "api.github.com" and len(parts) >= 3 and parts[0] == "repos":
        owner, repo = parts[1], parts[2]
    else:
        return None

    repo = re.sub(r"\.git$", "", repo)
    if not owner or not repo:
        return None
    return f"github.com/{owner}/{repo}"


def _as_strings(value) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [item.strip() for item in value if isinstance(item, str) and item.strip()]
    return []


def _format_score(score: float) -> str:
    return str(int(score)) if score.is_integer() else str(score)


def inspect_celix_bundles(
    explicit_paths: list[str],
    directories: list[str],
) -> tuple[list[Evidence], list[CelixBundleRecord]]:
    evidence: list[Evidence] = []
    records: list[CelixBundleRecord] = []
    candidates: dict[Path, bool] = {}

    for value in explicit_paths:
        candidates[Path(value).expanduser().resolve()] = True

    for value in directories:
        directory = Path(value).expanduser().resolve()
        if not directory.is_dir():
            evidence.append(Evidence(
                f"celix-bundle-dir:{_display_path(directory)}",
                "celix-bundle-discovery",
                "FAIL",
                "Celix bundle discovery directory does not exist",
                (_display_path(directory),),
            ))
            continue
        for path in sorted(directory.rglob("*.zip")):
            candidates.setdefault(path.resolve(), False)

    seen_refs: dict[str, str] = {}
    for path, explicit in sorted(
        candidates.items(),
        key=lambda item: item[0].as_posix(),
    ):
        if not path.is_file():
            evidence.append(Evidence(
                f"celix-bundle-file:{_display_path(path)}",
                "celix-bundle-identity",
                "FAIL",
                "Celix bundle path does not exist",
                (_display_path(path),),
            ))
            continue

        try:
            record, checks = _inspect_celix_bundle(path)
        except _NotCelixBundle:
            if explicit:
                evidence.append(Evidence(
                    f"celix-bundle-file:{_display_path(path)}",
                    "celix-bundle-identity",
                    "FAIL",
                    "ZIP does not contain META-INF/MANIFEST.json",
                    (_display_path(path),),
                ))
            continue
        except (OSError, zipfile.BadZipFile, json.JSONDecodeError, ValueError) as exc:
            evidence.append(Evidence(
                f"celix-bundle-file:{_display_path(path)}",
                "celix-bundle-identity",
                "FAIL",
                f"Celix bundle could not be inspected: {type(exc).__name__}",
                (_display_path(path),),
            ))
            continue

        previous = seen_refs.get(record.reference)
        if previous is not None:
            evidence.append(Evidence(
                record.reference,
                "celix-bundle-identity",
                "FAIL",
                "duplicate Celix symbolic-name/version identity",
                (previous, record.path),
            ))
            continue

        seen_refs[record.reference] = record.path
        records.append(record)
        evidence.extend(checks)

    records.sort(key=lambda item: (item.symbolic_name, item.version, item.path))
    if records:
        bundle_set = _celix_bundle_set_identity(records)
        bundle_set_sha = canonical_sha256(bundle_set)
        evidence.append(Evidence(
            "celix-bundle-set",
            "celix-bundle-set",
            "PASS",
            (
                f"bundle set binds {len(records)} Celix bundle(s); "
                f"sha256 {bundle_set_sha}"
            ),
            (f"sha256:{bundle_set_sha}",),
        ))

    evidence.sort(key=lambda item: (item.reference, item.check))
    return evidence, records


class _NotCelixBundle(Exception):
    pass


def _inspect_celix_bundle(
    path: Path,
) -> tuple[CelixBundleRecord, list[Evidence]]:
    archive_sha = _sha256_file(path)

    with zipfile.ZipFile(path) as archive:
        infos = [info for info in archive.infolist() if not info.is_dir()]
        names = [info.filename.replace("\\", "/") for info in infos]
        if "META-INF/MANIFEST.json" not in names:
            raise _NotCelixBundle()

        layout_errors = _celix_archive_layout_errors(archive, infos)
        manifest_raw = archive.read("META-INF/MANIFEST.json")
        manifest = json.loads(manifest_raw.decode("utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("Celix manifest must be a JSON object")

        symbolic = _manifest_string(manifest, "CELIX_BUNDLE_SYMBOLIC_NAME")
        version = _normalize_celix_version(
            _manifest_string(manifest, "CELIX_BUNDLE_VERSION")
        )
        manifest_version = _normalize_celix_version(
            _manifest_string(manifest, "CELIX_BUNDLE_MANIFEST_VERSION")
        )
        activator = _manifest_optional_string(
            manifest,
            "CELIX_BUNDLE_ACTIVATOR_LIBRARY",
        )
        private_libraries = tuple(sorted(_manifest_string_list(
            manifest,
            "CELIX_BUNDLE_PRIVATE_LIBRARIES",
        )))

        if not symbolic or not version or not manifest_version:
            raise ValueError("Celix manifest is missing required bundle identity fields")

        normalized_names = set(names)
        missing: list[str] = []
        if activator and activator.replace("\\", "/") not in normalized_names:
            missing.append(activator)
        for library in private_libraries:
            if library.replace("\\", "/") not in normalized_names:
                missing.append(library)

        members: list[tuple[str, str]] = []
        info_by_name: dict[str, zipfile.ZipInfo] = {}
        for info in sorted(infos, key=lambda item: item.filename.replace("\\", "/")):
            normalized = info.filename.replace("\\", "/")
            data = archive.read(info)
            info_by_name[normalized] = info
            members.append((normalized, hashlib.sha256(data).hexdigest()))

        library_sonames: list[tuple[str, str]] = []
        for normalized, info in sorted(info_by_name.items()):
            if _zip_info_is_symlink(info):
                continue
            soname = _elf_soname(archive.read(info))
            if soname:
                library_sonames.append((normalized, soname))

        bundle_content_sha = _celix_bundle_content_sha256(archive, infos)

    manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
    record = CelixBundleRecord(
        path=_display_path(path),
        symbolic_name=symbolic,
        version=version,
        manifest_version=manifest_version,
        activator=activator,
        private_libraries=private_libraries,
        library_sonames=tuple(sorted(library_sonames)),
        archive_sha256=archive_sha,
        bundle_content_sha256=bundle_content_sha,
        manifest_sha256=manifest_sha,
        members=tuple(members),
    )

    checks: list[Evidence] = []
    checks.append(Evidence(
        record.reference,
        "celix-archive-layout",
        "FAIL" if layout_errors else "PASS",
        (
            "; ".join(layout_errors)
            if layout_errors
            else f"bundle archive has {len(members)} safe file member(s)"
        ),
        (record.path, f"archive-sha256:{record.archive_sha256}"),
    ))
    checks.append(Evidence(
        record.reference,
        "celix-manifest",
        "PASS",
        (
            f"manifest identity {symbolic}@{version}; "
            f"manifest-version={manifest_version}"
        ),
        (
            record.path,
            f"manifest-sha256:{record.manifest_sha256}",
        ),
    ))
    checks.append(Evidence(
        record.reference,
        "celix-library-closure",
        "FAIL" if missing else "PASS",
        (
            "manifest declares missing bundle library member(s): "
            + ", ".join(sorted(missing))
            if missing
            else (
                "manifest activator/private-library references are present"
                if activator or private_libraries
                else "resource-only bundle has no manifest library references"
            )
        ),
        (
            record.path,
            *tuple(f"missing-member:{name}" for name in sorted(set(missing))),
        ),
    ))
    checks.append(Evidence(
        record.reference,
        "celix-bundle-content",
        "FAIL" if layout_errors else "PASS",
        (
            "FCR-compatible bundle content digest "
            f"{record.bundle_content_sha256}; archive sha256 {record.archive_sha256}"
        ),
        (
            record.path,
            f"sha256:{record.bundle_content_sha256}",
            f"archive-sha256:{record.archive_sha256}",
        ),
    ))
    return record, checks


def _celix_bundle_content_sha256(
    archive: zipfile.ZipFile,
    infos: list[zipfile.ZipInfo],
) -> str:
    """Match fineract-celix fcr.bundle-content.v1 over extracted bundle files."""
    digest = hashlib.sha256()
    _sha256_add_length_prefixed(digest, b"fcr.bundle-content.v1")

    for info in sorted(infos, key=lambda item: item.filename.replace("\\", "/")):
        normalized = info.filename.replace("\\", "/")
        if _zip_info_is_symlink(info):
            continue
        data = archive.read(info)
        _sha256_add_length_prefixed(digest, normalized.encode("utf-8"))
        _sha256_add_length_prefixed(digest, data)

    return digest.hexdigest()


def _sha256_add_length_prefixed(digest, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, byteorder="big", signed=False))
    digest.update(value)


def _zip_info_is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def _elf_soname(data: bytes) -> str | None:
    """Return DT_SONAME from a well-formed ELF object, if present."""
    if len(data) < 16 or data[:4] != b"\x7fELF":
        return None

    elf_class = data[4]
    data_encoding = data[5]
    if data_encoding == 1:
        endian = "<"
    elif data_encoding == 2:
        endian = ">"
    else:
        return None

    try:
        if elf_class == 1:
            section_offset = struct.unpack_from(endian + "I", data, 32)[0]
            section_entry_size = struct.unpack_from(endian + "H", data, 46)[0]
            section_count = struct.unpack_from(endian + "H", data, 48)[0]
            section_format = endian + "IIIIIIIIII"
            dynamic_format = endian + "iI"
        elif elf_class == 2:
            section_offset = struct.unpack_from(endian + "Q", data, 40)[0]
            section_entry_size = struct.unpack_from(endian + "H", data, 58)[0]
            section_count = struct.unpack_from(endian + "H", data, 60)[0]
            section_format = endian + "IIQQQQIIQQ"
            dynamic_format = endian + "qQ"
        else:
            return None

        section_size = struct.calcsize(section_format)
        dynamic_size = struct.calcsize(dynamic_format)
        if (
            section_count == 0
            or section_entry_size < section_size
            or section_offset > len(data)
        ):
            return None

        sections: list[tuple[int, int, int, int, int]] = []
        for index in range(section_count):
            offset = section_offset + index * section_entry_size
            if offset + section_size > len(data):
                return None
            values = struct.unpack_from(section_format, data, offset)
            section_type = int(values[1])
            file_offset = int(values[4])
            byte_size = int(values[5])
            link = int(values[6])
            entry_size = int(values[9])
            sections.append((
                section_type,
                file_offset,
                byte_size,
                link,
                entry_size,
            ))

        for section_type, file_offset, byte_size, link, entry_size in sections:
            if section_type != 6:  # SHT_DYNAMIC
                continue
            if link < 0 or link >= len(sections):
                return None
            if file_offset + byte_size > len(data):
                return None

            _, string_offset, string_size, _, _ = sections[link]
            if string_offset + string_size > len(data):
                return None

            stride = entry_size or dynamic_size
            if stride < dynamic_size:
                return None
            position = file_offset
            end = file_offset + byte_size
            while position + dynamic_size <= end:
                tag, value = struct.unpack_from(dynamic_format, data, position)
                if tag == 0:  # DT_NULL
                    break
                if tag == 14:  # DT_SONAME
                    if value < 0 or value >= string_size:
                        return None
                    start = string_offset + int(value)
                    limit = string_offset + string_size
                    nul = data.find(b"\x00", start, limit)
                    if nul < 0:
                        return None
                    try:
                        soname = data[start:nul].decode("utf-8")
                    except UnicodeDecodeError:
                        return None
                    return soname or None
                position += stride
    except (IndexError, OverflowError, struct.error, ValueError):
        return None

    return None


def _celix_archive_layout_errors(
    archive: zipfile.ZipFile,
    infos: list[zipfile.ZipInfo],
) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()

    for info in infos:
        name = info.filename
        normalized = name.replace("\\", "/")
        parts = [part for part in normalized.split("/") if part]
        if (
            normalized.startswith("/")
            or re.match(r"^[A-Za-z]:/", normalized)
            or ".." in parts
        ):
            errors.append(f"unsafe bundle member path: {name}")

        if normalized in seen:
            errors.append(f"duplicate bundle member path: {name}")
        seen.add(normalized)

        if _zip_info_is_symlink(info):
            try:
                target = archive.read(info).decode("utf-8")
            except UnicodeDecodeError:
                errors.append(f"bundle symlink target is not UTF-8: {name}")
                continue
            if _celix_symlink_escapes(normalized, target):
                errors.append(f"bundle symlink escapes bundle root: {name} -> {target}")

    return errors


def _celix_symlink_escapes(name: str, target: str) -> bool:
    target = target.replace("\\", "/")
    if target.startswith("/") or re.match(r"^[A-Za-z]:/", target):
        return True

    base = [part for part in name.split("/")[:-1] if part]
    for part in target.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not base:
                return True
            base.pop()
        else:
            base.append(part)
    return False

def _manifest_string(manifest: dict, key: str) -> str:
    value = manifest.get(key)
    if not isinstance(value, str):
        return ""
    return value.strip()


def _manifest_optional_string(manifest: dict, key: str) -> str | None:
    value = _manifest_string(manifest, key)
    return value or None


def _manifest_string_list(manifest: dict, key: str) -> list[str]:
    value = manifest.get(key)
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [
            item.strip()
            for item in value
            if isinstance(item, str) and item.strip()
        ]
    raise ValueError(f"{key} must be a string or list of strings")


def _normalize_celix_version(value: str) -> str:
    value = value.strip()
    match = re.fullmatch(r"version<(.+)>", value)
    return match.group(1).strip() if match else value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _celix_soname_collisions(
    bundles: Iterable[CelixBundleRecord],
) -> list[dict]:
    by_soname: dict[str, list[dict]] = {}
    seen: set[tuple[str, str, str]] = set()

    for bundle in bundles:
        member_digests = dict(bundle.members)
        for member_path, soname in bundle.library_sonames:
            digest = member_digests.get(member_path)
            if not digest:
                continue
            identity = (bundle.reference, member_path, digest)
            if identity in seen:
                continue
            seen.add(identity)
            by_soname.setdefault(soname, []).append({
                "bundle": bundle.reference,
                "path": member_path,
                "sha256": digest,
            })

    collisions: list[dict] = []
    for soname, libraries in sorted(by_soname.items()):
        artifacts = {
            (item["bundle"], item["path"])
            for item in libraries
        }
        digests = {item["sha256"] for item in libraries}
        if len(artifacts) > 1 and len(digests) > 1:
            collisions.append({
                "soname": soname,
                "libraries": sorted(
                    libraries,
                    key=lambda item: (
                        item["bundle"],
                        item["path"],
                        item["sha256"],
                    ),
                ),
            })
    return collisions


def inspect_celix_containers(
    config_paths: list[str],
    bundles: list[CelixBundleRecord],
) -> tuple[list[Evidence], list[CelixContainerRecord]]:
    evidence: list[Evidence] = []
    records: list[CelixContainerRecord] = []

    by_basename: dict[str, list[CelixBundleRecord]] = {}
    by_reference = {bundle.reference: bundle for bundle in bundles}
    for bundle in bundles:
        by_basename.setdefault(Path(bundle.path).name, []).append(bundle)

    for value in config_paths:
        path = Path(value).expanduser().resolve()
        reference = f"celix-container:{_display_path(path)}"

        if not path.is_file():
            evidence.append(Evidence(
                reference,
                "celix-container-composition",
                "FAIL",
                "Celix container config does not exist",
                (_display_path(path),),
            ))
            continue

        try:
            config = _read_celix_container_config(path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            evidence.append(Evidence(
                reference,
                "celix-container-composition",
                "FAIL",
                f"Celix container config could not be parsed: {type(exc).__name__}",
                (_display_path(path),),
            ))
            continue

        if not isinstance(config, dict):
            evidence.append(Evidence(
                reference,
                "celix-container-composition",
                "FAIL",
                "Celix container config must resolve to a key/value object",
                (_display_path(path),),
            ))
            continue

        declared = _celix_configured_bundle_locations(config)
        entries: list[dict] = []
        resolved_bundles: list[CelixBundleRecord] = []
        unresolved: list[str] = []
        ambiguous: list[str] = []

        for mode, level, order, location in declared:
            bundle = _resolve_celix_bundle_location(
                location,
                path.parent,
                bundles,
                by_basename,
                by_reference,
            )
            if bundle == "AMBIGUOUS":
                ambiguous.append(location)
                entries.append({
                    "mode": mode,
                    "level": level,
                    "order": order,
                    "location": location,
                    "bundle": None,
                })
                continue
            if bundle is None:
                unresolved.append(location)
                entries.append({
                    "mode": mode,
                    "level": level,
                    "order": order,
                    "location": location,
                    "bundle": None,
                })
                continue

            resolved_bundles.append(bundle)
            entries.append({
                "mode": mode,
                "level": level,
                "order": order,
                "location": location,
                "bundle": bundle.reference,
                "bundle_content_sha256": bundle.bundle_content_sha256,
            })

        config_sha = _sha256_file(path)
        composition_sha = canonical_sha256(entries)
        status = "FAIL" if unresolved or ambiguous else "PASS"
        if unresolved:
            summary = (
                f"container composition has {len(unresolved)} unresolved bundle(s)"
            )
        elif ambiguous:
            summary = (
                f"container composition has {len(ambiguous)} ambiguous bundle(s)"
            )
        else:
            summary = (
                f"container composition binds {len(entries)} bundle placement(s); "
                f"sha256 {composition_sha}"
            )

        locations = [
            _display_path(path),
            f"config-sha256:{config_sha}",
            f"sha256:{composition_sha}",
        ]
        locations.extend(
            f"bundle:{entry['bundle']}:{entry['bundle_content_sha256']}"
            for entry in entries
            if entry.get("bundle") and entry.get("bundle_content_sha256")
        )
        locations.extend(f"unresolved:{item}" for item in unresolved)
        locations.extend(f"ambiguous:{item}" for item in ambiguous)

        record = CelixContainerRecord(
            path=_display_path(path),
            config_sha256=config_sha,
            composition_sha256=composition_sha,
            bundles=tuple(entries),
        )
        records.append(record)
        evidence.append(Evidence(
            record.reference,
            "celix-container-composition",
            status,
            summary,
            tuple(locations),
        ))

        collisions = _celix_soname_collisions(resolved_bundles)
        if collisions:
            collision_status = "FAIL"
            collision_summary = (
                f"runtime composition contains {len(collisions)} divergent "
                "ELF SONAME collision(s)"
            )
        elif unresolved or ambiguous:
            collision_status = "UNKNOWN"
            collision_summary = (
                "runtime library collision check is incomplete because "
                "one or more configured bundles were unresolved"
            )
        else:
            collision_status = "PASS"
            collision_summary = (
                "no divergent ELF SONAME collisions across configured bundles"
            )

        collision_locations = [_display_path(path)]
        for collision in collisions:
            soname = collision["soname"]
            for library in collision["libraries"]:
                collision_locations.append(
                    "soname:"
                    f"{soname}:{library['bundle']}:{library['path']}:"
                    f"{library['sha256']}"
                )

        evidence.append(Evidence(
            record.reference,
            "celix-runtime-library-collision",
            collision_status,
            collision_summary,
            tuple(collision_locations),
        ))

    records.sort(key=lambda item: item.path)
    evidence.sort(key=lambda item: (item.reference, item.check))
    return evidence, records


def _read_celix_container_config(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")

    if path.suffix.lower() == ".json" or text.lstrip().startswith("{"):
        value = json.loads(text)
        if not isinstance(value, dict):
            raise ValueError("Celix JSON config must be an object")
        return value

    embedded = _extract_celix_embedded_json(text)
    if embedded is not None:
        return embedded

    if path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx"}:
        raise ValueError(
            "Celix generated container source does not contain "
            "CELIX_MULTI_LINE_STRING JSON"
        )

    config: dict[str, str] = {}
    pending = ""
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if pending:
            line = pending + line.lstrip()
            pending = ""
        if line.endswith("\\"):
            pending = line[:-1]
            continue

        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("!"):
            continue

        split_at = None
        for separator in ("=", ":"):
            index = stripped.find(separator)
            if index >= 0 and (split_at is None or index < split_at):
                split_at = index
        if split_at is None:
            parts = stripped.split(None, 1)
            key = parts[0]
            value = parts[1] if len(parts) == 2 else ""
        else:
            key = stripped[:split_at].strip()
            value = stripped[split_at + 1:].strip()

        if not key:
            raise ValueError("Celix properties config contains an empty key")
        config[key] = value

    if pending:
        raise ValueError("Celix properties config ends with an unfinished continuation")
    return config


def _extract_celix_embedded_json(text: str) -> dict | None:
    marker = "CELIX_MULTI_LINE_STRING"
    search_from = 0
    start = None

    while True:
        marker_at = text.find(marker, search_from)
        if marker_at < 0:
            return None

        open_paren = text.find("(", marker_at + len(marker))
        if open_paren < 0:
            raise ValueError("malformed CELIX_MULTI_LINE_STRING invocation")

        candidate = open_paren + 1
        while candidate < len(text) and text[candidate].isspace():
            candidate += 1
        if candidate < len(text) and text[candidate] == "{":
            start = candidate
            break

        search_from = open_paren + 1

    if start is None:
        return None

    depth = 0
    in_string = False
    escaped = False
    end = None

    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = index + 1
                break
            if depth < 0:
                raise ValueError("malformed embedded Celix JSON")

    if end is None:
        raise ValueError("unterminated embedded Celix JSON object")

    value = json.loads(text[start:end])
    if not isinstance(value, dict):
        raise ValueError("embedded Celix JSON config must be an object")
    return value


def _celix_configured_bundle_locations(
    config: dict,
) -> list[tuple[str, int | None, int, str]]:
    result: list[tuple[str, int | None, int, str]] = []

    for level in range(7):
        key = f"CELIX_AUTO_START_{level}"
        for order, location in enumerate(_split_celix_locations(config.get(key))):
            result.append(("auto-start", level, order, location))

    for order, location in enumerate(
        _split_celix_locations(config.get("CELIX_AUTO_INSTALL"))
    ):
        result.append(("auto-install", None, order, location))

    return result


def _split_celix_locations(value) -> list[str]:
    if not isinstance(value, str) or not value.strip():
        return []
    if "," in value:
        return [part.strip() for part in value.split(",") if part.strip()]
    return [part for part in value.split() if part]


def _resolve_celix_bundle_location(
    location: str,
    config_dir: Path,
    bundles: list[CelixBundleRecord],
    by_basename: dict[str, list[CelixBundleRecord]],
    by_reference: dict[str, CelixBundleRecord],
):
    if location in by_reference:
        return by_reference[location]

    location_path = Path(location)
    basename = location_path.name
    candidates = by_basename.get(basename, [])
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        return "AMBIGUOUS"

    try:
        configured = (config_dir / location_path).resolve()
    except OSError:
        configured = None

    if configured is not None:
        for bundle in bundles:
            try:
                if Path(bundle.path).resolve() == configured:
                    return bundle
            except OSError:
                continue

    return None


def summarize(evidence: list[Evidence]) -> dict:
    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "UNKNOWN": 0}
    for item in evidence:
        counts[item.status] = counts.get(item.status, 0) + 1

    refs = sorted({item.reference for item in evidence})
    package_refs = [
        reference
        for reference in refs
        if not reference.startswith("celix-bundle:")
        and not reference.startswith("celix-bundle-set")
        and not reference.startswith("celix-container:")
        and not reference.startswith("celix-bundle-file:")
        and not reference.startswith("celix-bundle-dir:")
    ]
    bundle_refs = [
        reference for reference in refs
        if reference.startswith("celix-bundle:")
    ]
    container_refs = [
        reference for reference in refs
        if reference.startswith("celix-container:")
    ]
    return {
        "packages": len(package_refs),
        "celix_bundles": len(bundle_refs),
        "celix_containers": len(container_refs),
        "subjects": len(package_refs) + len(bundle_refs) + len(container_refs),
        "observations": len(evidence),
        "counts": counts,
        "evidence": [item.json() for item in evidence],
    }


def write_ndjson(path: str, evidence: list[Evidence]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(
        json.dumps(item.json(), sort_keys=True, separators=(",", ":")) + "\n"
        for item in evidence
    )
    target.write_text(payload, encoding="utf-8")


def _celix_bundle_subject(bundle: CelixBundleRecord) -> dict:
    return {
        "reference": bundle.reference,
        "bundle_content_sha256": bundle.bundle_content_sha256,
    }


def _celix_container_subject(container: CelixContainerRecord) -> dict:
    return {
        "config_sha256": container.config_sha256,
        "composition_sha256": container.composition_sha256,
    }


def _celix_subject_identity(
    bundles: list[CelixBundleRecord],
    containers: list[CelixContainerRecord],
) -> dict:
    return {
        "bundles": [
            _celix_bundle_subject(bundle)
            for bundle in sorted(
                bundles,
                key=lambda item: (item.symbolic_name, item.version, item.path),
            )
        ],
        "containers": [
            _celix_container_subject(container)
            for container in sorted(containers, key=lambda item: item.path)
        ],
    }


def _celix_bundle_set_identity(
    bundles: list[CelixBundleRecord],
) -> list[dict]:
    return [
        {
            "reference": bundle.reference,
            "bundle_content_sha256": bundle.bundle_content_sha256,
        }
        for bundle in sorted(
            bundles,
            key=lambda item: (item.symbolic_name, item.version, item.path),
        )
    ]


def _celix_bundle_identity(bundle: CelixBundleRecord) -> dict:
    return {
        "reference": bundle.reference,
        "symbolic_name": bundle.symbolic_name,
        "version": bundle.version,
        "manifest_version": bundle.manifest_version,
        "activator": bundle.activator,
        "private_libraries": list(bundle.private_libraries),
        "library_sonames": [
            {"path": path, "soname": soname}
            for path, soname in bundle.library_sonames
        ],
        "archive_sha256": bundle.archive_sha256,
        "bundle_content_sha256": bundle.bundle_content_sha256,
        "manifest_sha256": bundle.manifest_sha256,
        "members": [
            {"path": path, "sha256": digest}
            for path, digest in bundle.members
        ],
    }


def _celix_container_identity(container: CelixContainerRecord) -> dict:
    return {
        "config_sha256": container.config_sha256,
        "composition_sha256": container.composition_sha256,
        "bundles": list(container.bundles),
    }


def write_receipt(
    path: str,
    serialized_graph: dict,
    evidence: list[Evidence],
    *,
    celix_bundles: list[CelixBundleRecord] | None = None,
    celix_containers: list[CelixContainerRecord] | None = None,
) -> None:
    identity = graph_identity(serialized_graph)
    celix_bundles = celix_bundles or []
    celix_containers = celix_containers or []
    celix_identity = _celix_subject_identity(
        celix_bundles,
        celix_containers,
    )
    receipt = {
        "schema": "https://windanvil.com/schemas/conan-assurance-receipt/v2",
        "graph_sha256": canonical_sha256(identity),
        "celix_subject_sha256": (
            canonical_sha256(celix_identity)
            if celix_bundles or celix_containers
            else None
        ),
        "subject_sha256": canonical_sha256({
            "conan_graph": identity,
            "celix": celix_identity,
        }),
        "evidence_sha256": evidence_digest(evidence),
        "packages": _receipt_packages(identity, evidence),
        "celix_bundles": [bundle.json() for bundle in celix_bundles],
        "celix_containers": [container.json() for container in celix_containers],
    }

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_celix_provenance(
    path: str,
    bundles: list[CelixBundleRecord],
    containers: list[CelixContainerRecord],
    evidence: list[Evidence],
) -> None:
    bundle_identity = [
        _celix_bundle_identity(bundle)
        for bundle in sorted(
            bundles,
            key=lambda item: (item.symbolic_name, item.version, item.path),
        )
    ]
    container_identity = [
        _celix_container_identity(container)
        for container in sorted(containers, key=lambda item: item.path)
    ]
    subject_identity = _celix_subject_identity(bundles, containers)
    celix_evidence = [
        item
        for item in evidence
        if item.reference.startswith("celix-")
    ]
    predicate = {
        "schema": "https://windanvil.com/predicates/celix-runtime/v1",
        "subject_sha256": canonical_sha256(subject_identity),
        "bundle_set_sha256": canonical_sha256([
            _celix_bundle_subject(bundle)
            for bundle in sorted(
                bundles,
                key=lambda item: (item.symbolic_name, item.version, item.path),
            )
        ]),
        "container_set_sha256": canonical_sha256([
            _celix_container_subject(container)
            for container in sorted(containers, key=lambda item: item.path)
        ]),
        "evidence_sha256": evidence_digest(celix_evidence),
        "bundles": bundle_identity,
        "containers": container_identity,
    }

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(predicate, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

def write_provenance(
    path: str,
    serialized_graph: dict,
    evidence: list[Evidence],
    rebuild_records: list[RebuildRecord],
) -> None:
    predicate = {
        "schema": "https://windanvil.com/predicates/conan-rebuild/v1",
        "graph_sha256": canonical_sha256(graph_identity(serialized_graph)),
        "evidence_sha256": evidence_digest(evidence),
        "rebuilds": [
            {
                **asdict(record),
                "rebuild_payload_sha256": list(record.rebuild_payload_sha256),
                "rebuild_package_revisions": list(record.rebuild_package_revisions),
                "rebuild_log_sha256": list(record.rebuild_log_sha256),
            }
            for record in rebuild_records
        ],
    }

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(predicate, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def graph_identity(serialized_graph: dict) -> list[dict]:
    packages: list[dict] = []
    for _, node in sorted(
        serialized_graph.get("nodes", {}).items(),
        key=lambda item: str(item[0]),
    ):
        reference = _reference(node)
        if reference is None:
            continue
        packages.append(
            {
                "reference": reference,
                "recipe_revision": node.get("rrev"),
                "package_id": node.get("package_id"),
                "package_revision": node.get("prev"),
                "context": node.get("context"),
                "settings": node.get("settings") or {},
                "options": node.get("options") or {},
            }
        )
    return sorted(packages, key=lambda item: item["reference"])


def canonical_sha256(value) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _receipt_packages(
    identity: list[dict],
    evidence: list[Evidence],
) -> list[dict]:
    by_reference: dict[str, dict[str, Evidence]] = {}
    for item in evidence:
        by_reference.setdefault(item.reference, {})[item.check] = item

    packages: list[dict] = []
    for package in identity:
        checks = by_reference.get(package["reference"], {})
        bound = dict(package)
        bound["source_artifact_sha256"] = _evidence_sha256(
            checks.get("source-artifact-bytes")
        )
        bound["package_tree_sha256"] = _evidence_sha256(
            checks.get("package-bytes")
        )
        bound["package_payload_sha256"] = _location_sha256(
            checks.get("consumed-binary-reproduction")
        )
        bound["checks"] = {
            name: {
                "status": item.status,
                "summary": item.summary,
            }
            for name, item in sorted(checks.items())
        }
        packages.append(bound)
    return packages


def _evidence_sha256(item: Evidence | None) -> str | None:
    if item is None or item.status != "PASS":
        return None
    return _location_sha256(item)


def _location_sha256(item: Evidence | None) -> str | None:
    if item is None:
        return None
    for location in item.locations:
        if location.startswith("sha256:"):
            value = location.split(":", 1)[1]
            if SHA256_RE.fullmatch(value):
                return value
    return None


def _print_text(result: dict) -> None:
    out = ConanOutput()
    counts = result["counts"]
    out.info(
        "assurance: "
        f"packages={result['packages']} "
        f"celix_bundles={result.get('celix_bundles', 0)} "
        f"celix_containers={result.get('celix_containers', 0)} "
        f"observations={result['observations']} "
        f"pass={counts['PASS']} "
        f"warn={counts['WARN']} "
        f"fail={counts['FAIL']} "
        f"unknown={counts['UNKNOWN']}"
    )
    for item in result["evidence"]:
        out.info(
            f"{item['reference']} {item['check']} "
            f"{item['status']}: {item['summary']}"
        )


def _enforce_policy(
    result: dict,
    *,
    fail_on_failure: bool,
    fail_on_unknown: bool,
) -> None:
    violations: list[str] = []
    counts = result["counts"]
    if fail_on_failure and counts["FAIL"]:
        violations.append(f"failed checks={counts['FAIL']}")
    if fail_on_unknown and counts["UNKNOWN"]:
        violations.append(f"unknown checks={counts['UNKNOWN']}")
    if violations:
        raise ConanException(
            "supply-chain assurance policy rejected graph: "
            + ", ".join(violations)
        )


def evidence_digest(evidence: Iterable[Evidence]) -> str:
    """Stable digest helper for tests and downstream evidence receipts."""
    payload = "".join(
        json.dumps(item.json(), sort_keys=True, separators=(",", ":")) + "\n"
        for item in sorted(evidence, key=lambda e: (e.reference, e.check))
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
