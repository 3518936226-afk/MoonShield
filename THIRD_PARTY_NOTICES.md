# Third-party notices and provenance

## Official MoonBit configuration parser

Repository: https://github.com/moonbitlang/parser

Commit: e5a83856b177acefaa24287b77a3bf33f205dc76

Components: moonbitlang/moon_config 0.4.6 and moonbitlang/lexer 0.4.5. Apache-2.0. Original LICENSE/README/AGENTS are retained in vendor/parser. No upstream NOTICE was present. upstream.lock.json pins every included original file.

Only lexer/tokens/moon.pkg in work/parser-build has rule/dev_build generator steps removed. The fixed commit already ships tokens.mbt. No upstream .mbt source is patched. vendor itself is immutable.

## Moonrun semantic port

The runtime string conversion and header algorithm in src/semantics.mbt derive from moonbitlang/moon at 738607b:

- crates/moonutil/src/moon_pkg/lexer.rs, unescape_string
- crates/moonutil/src/front_matter.rs, extract_mbtx_front_matter
- crates/moonrun/src/policy/config.rs for schema references

Copyright 2026 International Digital Economy Academy; Apache-2.0. Reference source files retain original headers in docs/runtime-reference. The MoonBit port changes implementation language, adds source-preserving diagnostics, redaction and explicit conservative handling of unimplemented formats. It does not claim an official endorsement.

## Compiled MoonBit core

The Wasm artifact includes linked MoonBit core code. License and full attribution notices (including applicable adapted code notices) are included in licenses/MoonBit-core-LICENSE and licenses/MoonBit-core-NOTICE. MoonBit compiler/Moonrun binaries are external prerequisites and are not redistributed in the compact package.

## Optional Windows executable launcher

The launcher is MoonShield-owned Apache-2.0 C source, built using the existing WinLibs GCC 15.2.0 / MinGW-w64 13.0.0 MSVCRT toolchain. Relevant MinGW-w64 copyright/license/AUTHORS and GCC GPLv3 plus Runtime Library Exception texts are included in licenses, with source URLs and hashes. No GCC distribution or compiler is bundled. The PowerShell entry point is also provided; auditing logic is not implemented in this launcher.

## Official static-only project corpus

Six original .mbtx samples from moonbitlang/moon commit 738607b3e4005a0343f09b744dbde641b38de64c are retained under examples/official-corpus with original LICENSE (Apache-2.0) and per-file source URL, size and SHA-256 in provenance.json. They are static data only; their bodies/imports are never compiled, downloaded or executed by tests.
