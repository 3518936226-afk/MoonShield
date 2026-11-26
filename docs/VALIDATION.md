# Validation and public evidence

The initial v1.2 local acceptance on Windows x64 used Moon/Moonrun 0.1.20261119 (738607b), moonc v0.10.22+124d61d05 and real Wasm permission probes. No Native result stands in for isolation.

| Layer | Passed |
|---|---|
| Owned MoonBit tests | 36/36 |
| Official config + lexer/basic/tokens tests | 99/99 |
| Original real Moonrun probes, 13 scenarios each repeated three times | 39/39 |
| CLI integration | 145/145 |
| Additional qualification | 39/39 |
| Release extraction / minimal launch / tamper checks | 10/10 |

Qualification consists of 18 static-only official corpus checks, 12 owned synthetic orders runtime checks, 6 schema runtime checks, and 3 clean-cwd/minimal-environment launch checks. These are not additional to the same 39 total. Official script bodies are never compiled or executed. Full local runtime records retain argv, cwd, exit code, stdout and stderr; only a reviewed summary is public to avoid leaking workstation paths.

Real failures retained locally include a missing unrelated.csv fixture (policy-load failure, not a valid denial) and PowerShell skipping executable invocation without PATHEXT. Fixtures and launcher were corrected, then repeated real-runtime checks passed. JSON optional-domain null is accepted by the pinned runtime but explicitly UNSUPPORTED by this auditor. No unsupported result is counted as successful audit coverage.

Reproduce from a fresh D-drive checkout with the pinned toolchain:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/bootstrap.ps1 -Download
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test.ps1 -Integration
```

Alternatively supply original offline archives or set MOONSHIELD_TOOLCHAIN to an existing exact pinned toolchain. Python 3 is developer-only and must already exist; no pip packages are installed. Default runtime scenarios repeat at least three times and save fresh records below evidence/. A compiler/fixture error cannot count as a sandbox denial. Failed runs remain NO-GO.

GitHub Actions is manually dispatched; actual remote run results and their captured evidence are shown in the Actions page. This document's initial local counts are not a claim that a remote run passed. Linux/macOS, another physical machine and other MoonBit versions remain untested. No-finding output is not a proof that a script is safe.
