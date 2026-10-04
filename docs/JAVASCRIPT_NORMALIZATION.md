# JavaScript change fingerprints

Raw hashes identify the exact downloaded bytes. Semantic hashes are conservative source fingerprints used to distinguish ordinary comment/horizontal formatting changes from changes worth reviewing. They do not prove runtime behavior or a vulnerability.

`javascript_normalization.py` recognizes a lexical subset: ASCII identifiers, numeric literals, punctuators, quoted strings, comments and whitespace. It preserves quoted string contents and escapes, token boundaries, and the presence of line terminators between tokens, including line terminators inside block comments. Numeric values and fields named `buildTime`, `buildTimestamp` or `compiledAt` are preserved. Diff rendering also preserves literal whitespace.

Slash syntax requiring a division/regular-expression grammar goal, templates, JSX/less-than syntax, unsupported tokens and incomplete literals use `raw_fallback`. The entire input is retained, including any previously scanned comments. Invalid UTF-8 uses the exact byte hash so replacement characters cannot merge distinct bodies. This deliberately trades formatting suppression for preserving changes when a parser would be needed. The relevant lexical goals and line-terminator rules are defined in the [ECMAScript lexical grammar](https://tc39.es/ecma262/2026/multipage/ecmascript-language-lexical-grammar.html).

Changed-JavaScript events record `semantic_comparison` as `changed`, `unchanged` or `unknown`. When either input requires fallback or the previous artifact is unavailable/unverified, `semantic_changed` is null and the URL is listed in `semantic-js-unknown.txt`. Stage metrics include `semantic_unknown` and `semantic_normalization_fallbacks`. Unknown comparisons receive neither the formatting/build-noise penalty nor the semantic-change evidence bonus. Raw changes, bytes and diffs remain available for review.

Comparisons re-fingerprint the previous verified CAS bytes under the current algorithm. Equal raw bytes never create a semantic-change event or advance `last_changed` solely because a stored digest is from an older algorithm. Resume upgrades verified completed artifacts offline, preserving their attempt/completion state and events. Work results record the normalization version, mode and reason.

Embedded Source Map content uses the same normalizer. Equal source/map bytes do not produce an algorithm-upgrade differential. Changed-source signals re-fingerprint verified previous/current source bytes and preserve `semantic_comparison` through advisory validation, so parser-dependent changes cannot gain a semantic-change priority bonus.

No JavaScript execution, parser subprocess, notification delivery or target request is needed for normalization or its regression tests. The application/schema versions remain 8.8.2/18; normalization metadata version 1 is additive and needs no database schema migration.
