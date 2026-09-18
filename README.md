# Supply Chain Verification for Conan

A Conan 2 custom command that turns a resolved C/C++ dependency graph into explicit, machine-enforceable supply-chain evidence.

**Current release:** `v0.4.0`

```bash
conan assurance --requires=zlib/1.3.1 -r=conancenter
```

The command complements Conan's built-in vulnerability audit and SBOM tooling. It focuses on recipe identity, source bytes, package bytes, upstream project posture, deterministic evidence receipts, and now Apache Celix bundle/runtime composition.

## Checks

The base command records:

- **recipe-revision** — concrete Conan recipe revision selected by the resolved graph.
- **source-digest** — version-matched `conandata.yml` source metadata is SHA-256 pinned.
- **openssf-scorecard** — supported GitHub upstreams resolve to a published OpenSSF Scorecard result.

With byte verification enabled, two stronger checks are added:

- **source-artifact-bytes** — downloads the source artifact and recomputes SHA-256 over the actual bytes.
- **package-bytes** — hashes the materialized Conan package file tree and binds it to package ID and package revision.

With clean rebuild verification enabled, two more checks are added:

- **rebuild-repeatability** — builds the same recipe in multiple independent clean Conan homes and compares package payload digests.
- **consumed-binary-reproduction** — compares that repeatable rebuild output to the package payload Conan actually consumed.

Statuses are deliberately narrow:

- `PASS` — the evidence was positively established.
- `FAIL` — a conclusive negative result, such as a digest mismatch or policy failure.
- `UNKNOWN` — evidence could not be established safely.

A timeout is never treated as proof that evidence is absent.

## Install

Conan custom commands live under `CONAN_HOME/extensions/commands`.

```bash
mkdir -p "$(conan config home)/extensions/commands"
cp extensions/commands/cmd_assurance.py "$(conan config home)/extensions/commands/"
conan assurance -h
```

## Verify actual source and package bytes

```bash
conan assurance \
  --requires=zlib/1.3.1 \
  -r=conancenter \
  --materialize-packages \
  --verify-source-bytes \
  --verify-package-bytes \
  --report=assurance.ndjson \
  --receipt=receipt.json
```
`--materialize-packages` performs a normal Conan install into the local cache first. Temporary generator output is isolated and removed automatically.

For a verified package, the receipt binds:

```text
recipe revision
  -> source archive SHA-256 recomputed from downloaded bytes
  -> resolved settings + options
  -> package ID + package revision
  -> SHA-256 of the materialized package file tree
```

That binding says what source bytes were verified and what package bytes were consumed. To test the missing source→build→binary link, use clean rebuild verification:

```bash
conan assurance \
  --requires=zlib/1.3.1 \
  -r=conancenter \
  --rebuild-package=zlib/1.3.1 \
  --rebuild-count=2 \
  --receipt=receipt.json \
  --provenance=provenance.json
```

Each rebuild runs in a fresh Conan home using the same recipe revision and profile. Conan-generated metadata files are excluded from the payload digest so timestamp-only manifest changes do not masquerade as binary differences.

The resulting predicate records the consumed payload digest, every clean rebuild payload digest, recipe/package revisions, rebuild log digests, and the observed builder toolchain. A PASS for `rebuild-repeatability` means the clean builds agree with each other. A separate PASS for `consumed-binary-reproduction` is required before claiming they reproduce the package Conan consumed.

## Apache Celix bundle and runtime assurance

Celix bundles are ZIP archives with a JSON manifest and, commonly, an activator/shared libraries. v0.4.0 makes those runtime artifacts first-class assurance subjects instead of stopping at the Conan package graph.

```bash
conan assurance \
  --requires=zlib/1.3.1 \
  --celix-bundle-dir=build-celix \
  --celix-container-config=build-celix/deploy/MyContainer/config.properties \
  --receipt=receipt.json \
  --celix-provenance=celix-provenance.json
```

Bundle discovery only treats ZIPs containing `META-INF/MANIFEST.json` as Celix bundles. Each bundle receives four checks:

- **celix-archive-layout** — rejects path traversal, duplicate normalized member paths, and symlinks that escape the bundle root.
- **celix-manifest** — binds `CELIX_BUNDLE_SYMBOLIC_NAME`, bundle version, manifest version, and the manifest digest.
- **celix-library-closure** — verifies every manifest-declared activator/private library exists in the bundle.
- **celix-bundle-content** — computes a canonical content digest independent of ZIP entry order and archive timestamps while also recording the exact ZIP SHA-256.

The canonical bundle-content digest follows the same `fcr.bundle-content.v1` length-prefixed file-content contract used by the existing `fineract-celix` assurance implementation. That lets the Conan-side evidence and Celix-side runtime evidence refer to the same bundle identity.

A **celix-bundle-set** observation then binds the ordered set of symbolic-name/version identities to their canonical content digests.

For Celix JSON snapshots or ordinary `.properties` framework/container configuration, `--celix-container-config` reads `CELIX_AUTO_START_0` through `CELIX_AUTO_START_6` plus `CELIX_AUTO_INSTALL`. The resulting **celix-container-composition** digest preserves start level, declaration order, symbolic bundle identity, and bundle content digest. Missing or ambiguous bundle references are a `FAIL`.

The Celix predicate type is:

```text
https://windanvil.com/predicates/celix-runtime/v1
```

Its subject digest binds the bundle set and configured runtime composition. Release-tag CI signs that subject with GitHub's short-lived OIDC/Sigstore attestation flow alongside the Conan rebuild attestation.

## Signed provenance

Release-tag CI uses GitHub's Sigstore-backed artifact attestation action to sign the custom Conan rebuild predicate against the consumed package payload digest. The predicate type is:

```text
https://windanvil.com/predicates/conan-rebuild/v1
```

The signature is created with a short-lived GitHub Actions OIDC identity; no long-lived signing key is stored in this repository.

## Demo

Requirements: Python 3.10+ and Conan 2.32+.

```bash
./scripts/demo.sh
```

The demo resolves and materializes `zlib/1.3.1` from ConanCenter, verifies source/package bytes, performs two independent clean-cache rebuilds, and builds a small Celix-format runtime fixture containing one real shared-library activator bundle plus one resource-only bundle.

On the current Ubuntu/GCC 13 demonstration environment, the two zlib clean rebuilds are byte-for-byte repeatable at the package-payload level, while their payload differs from the ConanCenter package selected by the same package ID. That remains an intentional FAIL.

The Celix side verifies both bundle manifests/layouts/library closure, computes canonical bundle identities, binds the two bundles into a start-level-aware container composition, and emits a separate runtime predicate. The full demo currently produces 17 observations: 16 PASS / 1 FAIL / 0 UNKNOWN.

It writes:

```text
demo/assurance.json
demo/assurance.ndjson
demo/receipt.json
demo/provenance.json
demo/celix-provenance.json
demo/celix/bundles/demo_service.zip
demo/celix/bundles/demo_config.zip
```
## Evidence receipt

The v2 JSON receipt contains the Conan graph digest, an overall subject digest, the evidence digest, package records, Celix bundle records, and Celix container-composition records.

A Conan package record includes recipe/package revisions, resolved settings/options, source-artifact SHA-256, complete package-tree SHA-256, package-payload SHA-256, and check summaries.

A Celix bundle record includes symbolic name/version, manifest and exact archive digests, canonical bundle-content digest, activator/private-library declarations, and every member digest. Container records bind the configuration-file digest to the ordered start/install composition.

The receipt is written before policy enforcement, so failed CI still leaves evidence to inspect.

## JSON / NDJSON output

Conan's formatter mechanism is supported:

```bash
conan assurance --requires=zlib/1.3.1 -r=conancenter --format=json
conan assurance --requires=zlib/1.3.1 -r=conancenter --format=ndjson
```

For CI, deterministic NDJSON and the receipt can be persisted together:

```bash
conan assurance . \
  --materialize-packages \
  --verify-source-bytes \
  --verify-package-bytes \
  --report=assurance.ndjson \
  --receipt=receipt.json \
  --fail-on-failure
```
## Policy

The default mode reports evidence without rejecting the graph. Example strict policy:

```bash
conan assurance . \
  --materialize-packages \
  --verify-source-bytes \
  --verify-package-bytes \
  --minimum-scorecard-score=7.0 \
  --fail-on-failure \
  --fail-on-unknown
```

Useful options:

| Option | Default | Meaning |
| --- | ---: | --- |
| `-r, --remote` | `conancenter` | Remote passed to Conan resolution |
| `--requires` | — | Resolve a requirement directly; repeatable |
| `--tool-requires` | — | Resolve a tool requirement directly; repeatable |
| `--graph-arg` | — | Extra argument passed to Conan graph/install operations |
| `--verify-source-bytes` | off | Download source artifacts and recompute SHA-256 |
| `--source-timeout` | `30` | Source download timeout in seconds |
| `--source-max-bytes` | 256 MiB | Maximum bytes downloaded per source artifact |
| `--materialize-packages` | off | Materialize resolved packages in the Conan cache |
| `--verify-package-bytes` | off | Hash package file trees; requires materialization |
| `--rebuild-package` | — | Rebuild a resolved name/version in independent clean Conan homes; repeatable |
| `--rebuild-count` | `2` | Number of clean rebuild attempts; minimum 2 when enabled |
| `--rebuild-timeout` | `900` | Timeout per clean rebuild in seconds |
| `--celix-bundle` | — | Inspect an explicit Celix bundle ZIP; repeatable |
| `--celix-bundle-dir` | — | Discover Celix bundle ZIPs recursively; repeatable |
| `--celix-container-config` | — | Bind a Celix JSON or `.properties` runtime configuration; repeatable |
| `--celix-provenance` | — | Write a Celix runtime-composition predicate suitable for attestation |
| `--minimum-scorecard-score` | `-1` | Optional minimum Scorecard score; negative disables threshold enforcement |
| `--scorecard-timeout` | `5` | Scorecard network timeout in seconds |
| `--skip-scorecard` | off | Disable Scorecard network lookup |
| `--report` | — | Write deterministic NDJSON evidence |
| `--receipt` | — | Write deterministic bound JSON receipt |
| `--provenance` | — | Write clean-rebuild predicate suitable for signed attestation |
| `--fail-on-failure` | off | Reject the graph when a check returns `FAIL` |
| `--fail-on-unknown` | off | Reject the graph when a check returns `UNKNOWN` |

## Scope and evidence limits

This project does **not** replace `conan audit`, and it does not treat a successful clean rebuild as universal reproducibility.

The source-artifact check verifies bytes from the recipe's declared mirrors against the declared SHA-256. If one mirror returns mismatched bytes, the check tries the remaining declared mirrors; a matching fallback can still establish the expected source artifact while recording the rejected mismatch. If every available mirror mismatches, the result is a hard `FAIL`; unreachable mirrors remain `UNKNOWN`.

The package check hashes the package tree Conan actually materialized in its local cache and binds that digest to the package ID and revision selected by the graph. Clean rebuild verification then asks two separate questions: whether repeated clean builds under the recorded builder environment agree with each other, and whether that output matches the package payload Conan consumed.

A PASS for `consumed-binary-reproduction` is byte-level reproduction under the recorded toolchain and profile. It is not proof that every independent builder or operating system will produce the same bytes. A signed attestation authenticates the observed predicate; it does not convert a failed reproduction check into a passing one.

The current Scorecard resolver supports GitHub source URLs, GitHub codeload URLs, and GitHub homepages. Non-GitHub projects remain `UNKNOWN` rather than being guessed.

The Conan Python API used by custom commands is documented but still experimental, so compatibility is tested against current Conan 2 releases.

## Why this fits Conan

Conan already exposes the dependency graph, recipe revision, package identity, recipe metadata, and `conandata` source metadata. The command uses those resolved facts instead of reparsing recipes from scratch.

Conan's native CVE auditing, CycloneDX SBOM generation, metadata storage, hooks, and package-signing extensions are complementary layers.

## License

Apache License 2.0.
