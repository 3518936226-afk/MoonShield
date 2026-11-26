# Changelog

## Repository bootstrap fix — 2026-11-26

- The first GitHub fresh-workspace run exposed enclosing moon.work discovery during the initial core bundle. Generate a minimal core workspace before bundling; original pinned source and archive hashes remain unchanged. Keep the failed run and verify the fix in a new clean runner.

## 1.2.0 — 2026-11-26

- Schema v2 separates risk, configuration errors, unsupported coverage and contextual information. Unsupported remains blocking at every threshold.
- Retains original configuration findings, projects only provable empty-rule direct denials; no guessed scope intersections or automatic inheritance discovery.
- Adds explicit metadata-only path inspection, preserving warnings for directories, aliases, missing paths and failures.
- Adds six pinned official static-only corpus scripts, an owned synthetic CSV workload and clean-cwd/minimal-environment checks.
- Preserves v1.0/v1.1 archives, raw failures and all prior evidence; no Git publication.

## 1.1.0 — 2026-11-26

- Added Chinese/English human-readable terminal reports with risk counts, effective policy, source locations and actionable explanations; JSON remains the default.
- Improved Markdown escaping and omitted unavailable coordinates instead of showing null:null.
- Fixed scan status under relaxed exit thresholds: an allowed exit code no longer labels existing findings as NO_FINDINGS.
- Added a seven-step evidence-preserving demo, explicit Fast skip mode, a three-minute presentation script and a factual project brief.
- Preserved v1.0.0 release/evidence. Permission decisions and runtime probes were not weakened.

## 1.0.0 — 2026-11-25

- Local MoonBit CLI: audit, scan, doctor and trusted runtime conformance.
- Official AST, original locations, pinned runtime string decoding and strict JSON.
- Explicit policy override and separate inherited ceilings.
- JSON/Markdown/SARIF, environment-literal redaction and exit thresholds.
- Argument-preserving EXE/PowerShell entry points; daily use needs no Python.
- Checksummed offline/opt-in online bootstrap and reproducible isolated build.
- Corrected the earlier process-conflict assumption: false spawn plus allow is not intrinsically invalid.
- Preserved real failures: API/build compatibility and reduced-environment process-helper failures. Writable project-local temp settings fixed the latter without broadening guest grants.
- No remote publication/CI/competition actions. TOML, legacy YAML and ambient inheritance discovery remain unsupported.
