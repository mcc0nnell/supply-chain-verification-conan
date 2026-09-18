# Supply Chain Verification for Conan

A Conan 2 custom command that turns a resolved C/C++ dependency graph into explicit, machine-enforceable supply-chain evidence.

**Current release:** `v0.3.0`

```bash
conan assurance --requires=zlib/1.3.1 -r=conancenter
```

The command complements Conan's built-in vulnerability audit and SBOM tooling. It focuses on recipe identity, source bytes, package bytes, upstream project posture, and deterministic evidence receipts.

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

The demo resolves and materializes `zlib/1.3.1` from ConanCenter, verifies source/package bytes, and performs two independent clean-cache rebuilds. It produces seven observations: the original five plus rebuild repeatability and consumed-binary reproduction.

On the current Ubuntu/GCC 13 demonstration environment, the two clean rebuilds are byte-for-byte repeatable at the package-payload level, while their payload differs from the ConanCenter package selected by the same package ID. The command reports that distinction as one PASS and one FAIL instead of collapsing both questions into a single provenance claim.

It writes:

```text
demo/assurance.json
demo/assurance.ndjson
demo/receipt.json
demo/provenance.json
```
## Evidence receipt

The JSON receipt contains a stable graph digest and evidence digest plus one bound record per resolved package. A package record includes:

- recipe revision
- package ID and package revision
- resolved settings and options
- recomputed source-artifact SHA-256 when verified
- complete package-tree SHA-256 when verified
- package-payload SHA-256 used for clean rebuild comparison
- status and summary for every check

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

The source-artifact check verifies the bytes obtained from a declared source mirror against the recipe's declared SHA-256. A mismatch is a hard `FAIL`; unreachable mirrors remain `UNKNOWN`.

The package check hashes the package tree Conan actually materialized in its local cache and binds that digest to the package ID and revision selected by the graph. Clean rebuild verification then asks two separate questions: whether repeated clean builds under the recorded builder environment agree with each other, and whether that output matches the package payload Conan consumed.

A PASS for `consumed-binary-reproduction` is byte-level reproduction under the recorded toolchain and profile. It is not proof that every independent builder or operating system will produce the same bytes. A signed attestation authenticates the observed predicate; it does not convert a failed reproduction check into a passing one.

The current Scorecard resolver supports GitHub source URLs, GitHub codeload URLs, and GitHub homepages. Non-GitHub projects remain `UNKNOWN` rather than being guessed.

The Conan Python API used by custom commands is documented but still experimental, so compatibility is tested against current Conan 2 releases.

## Why this fits Conan

Conan already exposes the dependency graph, recipe revision, package identity, recipe metadata, and `conandata` source metadata. The command uses those resolved facts instead of reparsing recipes from scratch.

Conan's native CVE auditing, CycloneDX SBOM generation, metadata storage, hooks, and package-signing extensions are complementary layers.

## License

Apache License 2.0.
