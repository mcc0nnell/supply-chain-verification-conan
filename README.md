# Supply Chain Verification for Conan

A Conan 2 custom command that turns a resolved C/C++ dependency graph into explicit supply-chain evidence.

```bash
conan assurance --requires=zlib/1.3.1 -r=conancenter
```

The command complements Conan's built-in vulnerability audit and SBOM tooling. It focuses on provenance-shaped evidence that is already present in the resolved recipe graph and upstream project metadata.

## Checks

For every resolved package, `conan assurance` currently records three observations:

- **recipe-revision** — verifies that the graph resolved a concrete Conan recipe revision.
- **source-digest** — verifies that version-matched `conandata.yml` source URLs are pinned by SHA-256.
- **openssf-scorecard** — resolves a supported GitHub upstream from source/homepage metadata and retrieves its published OpenSSF Scorecard result.

Statuses are deliberately narrow:

- `PASS` — the evidence was positively established.
- `FAIL` — the check reached a conclusive negative result, such as an unpinned source URL or a missing Scorecard result.
- `UNKNOWN` — evidence could not be established safely, including unsupported upstream metadata or transient network failures.

A timeout is not treated as proof that evidence is absent.

## Install

Conan custom commands live under `CONAN_HOME/extensions/commands`.

```bash
mkdir -p "$(conan config home)/extensions/commands"
cp extensions/commands/cmd_assurance.py "$(conan config home)/extensions/commands/"
conan assurance -h
```

## Demo

Requirements: Python 3.10+ and Conan 2.32+.

```bash
./scripts/demo.sh
```

The demo resolves `zlib/1.3.1` from ConanCenter and asserts three real observations:

1. the resolved recipe has a concrete revision;
2. its published source archive metadata is SHA-256 pinned;
3. one source location resolves to `github.com/madler/zlib`, and a live OpenSSF Scorecard result is retrieved.

It writes:

```
demo/assurance.json
demo/assurance.ndjson
```

## JSON / NDJSON output

Conan's formatter mechanism is supported:

```bash
conan assurance --requires=zlib/1.3.1 -r=conancenter --format=json
conan assurance --requires=zlib/1.3.1 -r=conancenter --format=ndjson
```

For CI, `--report` writes deterministic NDJSON before policy enforcement:

```bash
conan assurance \
  --requires=zlib/1.3.1 \
  --report=assurance.ndjson \
  --fail-on-failure
```

## Policy

The default mode reports evidence without rejecting the graph.

```bash
conan assurance . \
  --minimum-scorecard-score=7.0 \
  --fail-on-failure \
  --fail-on-unknown
```

Useful options:

| Option | Default | Meaning |
| --- | ---: | --- |
| `-r, --remote` | `conancenter` | Remote passed to `conan graph info` |
| `--requires` | — | Resolve a requirement directly; repeatable |
| `--tool-requires` | — | Resolve a tool requirement directly; repeatable |
| `--graph-arg` | — | Pass an extra argument verbatim to `conan graph info`; repeatable |
| `--minimum-scorecard-score` | `-1` | Optional minimum Scorecard score; negative disables threshold enforcement |
| `--scorecard-timeout` | `5` | Scorecard network timeout in seconds |
| `--skip-scorecard` | off | Disable Scorecard network lookup |
| `--report` | — | Write deterministic NDJSON evidence |
| `--fail-on-failure` | off | Reject the graph when a check returns `FAIL` |
| `--fail-on-unknown` | off | Reject the graph when a check returns `UNKNOWN` |

## Scope and evidence limits

This project does **not** replace `conan audit`, and it does not claim that a recipe's upstream metadata proves the identity of every produced binary.

The current source check verifies that the recipe's version-matched source metadata declares a valid SHA-256 alongside its source URL. It does not download the archive and independently recompute the digest.

The current Scorecard check supports GitHub source URLs, GitHub codeload URLs, and GitHub homepages. Non-GitHub projects remain `UNKNOWN` rather than being guessed.

The Conan Python API used by custom commands is documented but still experimental, so compatibility is tested against current Conan 2 releases.

## Why this fits Conan

Conan already exposes the resolved dependency graph, recipe revision, recipe metadata, and `conandata` source metadata in its graph serialization. The command uses those resolved facts rather than reparsing recipes from scratch.

Conan also has native CVE auditing, CycloneDX SBOM generation, metadata storage, hooks, and package-signing extensions. Those are complementary layers rather than things this command should duplicate.

## License

Apache License 2.0.
