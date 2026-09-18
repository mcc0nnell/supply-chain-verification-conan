"""Conan supply-chain assurance custom command."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import urllib.error
import urllib.request
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
        "--report",
        help="Write deterministic NDJSON evidence to this path before policy enforcement",
    )
    parser.add_argument(
        "--receipt",
        help="Write a deterministic JSON receipt binding graph identity and evidence digests",
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
    if parsed.verify_package_bytes and not parsed.materialize_packages:
        raise ConanException(
            "--verify-package-bytes requires --materialize-packages "
            "so package bytes are present in the Conan cache"
        )

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
    result = summarize(evidence)

    if parsed.report:
        write_ndjson(parsed.report, evidence)
    if parsed.receipt:
        write_receipt(parsed.receipt, serialized, evidence)

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
                return Evidence(
                    reference,
                    "source-artifact-bytes",
                    "FAIL",
                    (
                        "downloaded source SHA-256 mismatch: "
                        f"expected {expected}, got {actual}"
                    ),
                    (url, f"sha256:{expected}", f"sha256:{actual}"),
                )

            verified_count += 1
            verified_locations.extend(
                [url, f"sha256:{actual}", f"bytes:{size}"]
            )
            break
        else:
            return Evidence(
                reference,
                "source-artifact-bytes",
                "UNKNOWN",
                last_problem,
                tuple(urls + [f"sha256:{expected}"]),
            )

    return Evidence(
        reference,
        "source-artifact-bytes",
        "PASS",
        (
            "downloaded source bytes match declared SHA-256"
            if verified_count == 1
            else f"{verified_count} downloaded source artifacts match declared SHA-256"
        ),
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
    digest = hashlib.sha256()
    files = 0
    total = 0

    for path in sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
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


def summarize(evidence: list[Evidence]) -> dict:
    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "UNKNOWN": 0}
    for item in evidence:
        counts[item.status] = counts.get(item.status, 0) + 1

    refs = sorted({item.reference for item in evidence})
    return {
        "packages": len(refs),
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


def write_receipt(
    path: str,
    serialized_graph: dict,
    evidence: list[Evidence],
) -> None:
    identity = graph_identity(serialized_graph)
    receipt = {
        "schema": "https://windanvil.com/schemas/conan-assurance-receipt/v1",
        "graph_sha256": canonical_sha256(identity),
        "evidence_sha256": evidence_digest(evidence),
        "packages": _receipt_packages(identity, evidence),
    }

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
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
