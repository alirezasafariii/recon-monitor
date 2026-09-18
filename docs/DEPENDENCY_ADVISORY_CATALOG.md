# Dependency Advisory Catalog

Recon Monitor keeps dependency advisory synchronization separate from target
Recon and Analysis execution.

## Runtime boundary

Analysis reads a local catalog only. It never fetches GitHub advisories while a
target is being scanned or analyzed.

```
GitHub Reviewed Advisories
        |
        | explicit catalog sync only
        v
normalized local snapshot
        |
        | offline runtime read
        v
Recon exact technology version
        |
        v
dependency_supply_chain Potential Finding
```

A catalog match is evidence that a stored exact component version falls inside
a reviewed affected-version range. It is not proof that the affected feature is
reachable or exploitable.

A catalog miss is never treated as proof that the component is safe.

## Synchronize the full reviewed catalog

```bash
./recon-monitor.sh analysis advisory-catalog-sync \
  --advisory-update-manifest
```

The sync traverses the GitHub Global Security Advisories reviewed cursor to
completion unless `--advisory-max-pages` is explicitly set to a positive
diagnostic cap.

The operation:

- contacts only GitHub's public advisory API;
- excludes withdrawn advisories;
- normalizes every valid affected package entry;
- deduplicates by GHSA, ecosystem and package;
- preserves unsupported affected-range syntax instead of dropping records;
- records whether each package entry has at least one range currently matchable
  by the runtime matcher;
- writes the catalog atomically;
- stores an SHA-256 digest over the normalized advisory records;
- does not contact Recon targets;
- does not change Analysis thresholds or confirmation policy.

## Inspect status without network access

```bash
./recon-monitor.sh analysis advisory-catalog-status
```

Important fields include:

- `source_sync_complete`
- `advisory_count`
- `product_count`
- `ecosystems`
- `supported_range_count`
- `partially_supported_range_count`
- `unsupported_range_count`
- `range_capability_by_ecosystem`
- `unsupported_range_samples`
- `integrity_valid`
- `source_last_updated_at`

`source_sync_complete=true` means the local snapshot traversed the complete
GitHub-reviewed API cursor for that sync. It does **not** mean the catalog is an
exhaustive list of every vulnerability source in existence.

## Alias registry

`data/dependency_advisory_aliases.json` maps package identities to common
technology-fingerprint aliases. Alias changes are explicit and reviewable; the
sync does not guess aliases from advisory prose.

## Runtime version matching

The runtime matcher is intentionally fail-closed. A target-side technology must
contain an exact version token. Stable numeric versions retain the broadest
support. For SemVer-compatible ecosystems, exact prerelease/build versions are
also evaluated with SemVer precedence, but a prerelease observation is admitted
only when the same OR branch contains an explicit prerelease boundary for that
numeric release line. This prevents a broad stable range such as
`>=1.0.0,<2.0.0` from silently admitting `1.5.0-beta.1`.

Qualified observed versions whose ecosystem-specific precedence is not modeled
exactly (for example RubyGems or Maven qualifier observations) remain
fail-closed rather than being coerced into stable numeric releases.

Advisory **boundaries** are evaluated with ecosystem-aware semantics:

- generic numeric comparator conjunctions, including single-component and
  extended numeric releases;
- SemVer-compatible ecosystems (Actions, Composer, Erlang/Hex, Go, npm,
  NuGet, Pub, Rust/Cargo and Swift), including prerelease boundaries, caret,
  tilde, wildcard, hyphen and OR ranges;
- Python/PyPI PEP 440 prerelease/post/dev boundaries and compatible-release
  (`~=`) ranges;
- RubyGems prerelease boundaries and pessimistic (`~>`) ranges;
- Maven known qualifier ordering and interval notation.

Range capability is reported as `full`, `partial` or `none`. Catalog
status recomputes this capability with the current matcher instead of trusting
the snapshot's older `range_match_supported` convenience flag, and reports
per-ecosystem counts plus bounded unsupported samples. A partial OR expression
may create a positive match only when the observed version matches a fully
understood branch. Conjunctions are never partially evaluated. Unknown
qualifiers, package-manager expressions or malformed boundaries remain
unsupported and cannot create target evidence. In particular, date-based
versions, distro-specific suffixes (for example Ubuntu/Debian-style package
revisions), development-branch aliases such as `x-dev`, and custom labels
without a documented ordering stay fail-closed rather than being guessed.

A normalized technology alias that exists in multiple ecosystems now abstains
unless identity can be narrowed by either an explicit observation ecosystem
hint or the reviewed fingerprint alias registry. A hint can only narrow
matching to that ecosystem, and a registry alias is accepted only when it maps
the fingerprint to exactly one of the candidate ecosystems. Catalog status
reports both unresolved cross-ecosystem ambiguity and aliases resolved by the
registry so this precision pressure stays observable.

The catalog remains indexed and cached so a full snapshot is not reparsed for
every technology observation. Expanding range syntax does not make a catalog
miss equivalent to safety and does not turn an advisory match into confirmed
exploitability.

## Automation

`.github/workflows/dependency-advisory-catalog.yml` performs a full sync:

- weekly;
- manually through `workflow_dispatch`;
- automatically when the sync/matcher/alias infrastructure changes on `main`.

When the snapshot changes, the workflow pushes:

```
automation/dependency-advisory-catalog
```

The automation branch contains only the catalog snapshot and corresponding
`MANIFEST.sha256` update. Normal pull-request CI remains the merge gate.

## Safety invariants

- catalog metadata is not target evidence by itself;
- research/benchmark corpora are not imported into runtime matching;
- sync performs no target contact;
- Analysis performs no advisory-network I/O;
- catalog miss does not mean safe;
- a dependency advisory match produces at most a Potential Finding unless
  separate evidence satisfies stronger validation requirements.