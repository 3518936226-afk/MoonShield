# Contributing

Use a project-local D workspace. Preserve old evidence and unrelated projects. Never add real credentials, auto-install dependencies, loosen lock hashes, replace Moonrun with Native isolation results, or count compiler failures as permission denials.

Run scripts/test.ps1. Developer CLI contracts additionally use scripts/test.ps1 -Integration with existing Python 3. Runtime scenarios repeat at least three times with argv/cwd/exit/stdout/stderr retained. New unsupported behavior must be visible and fail closed.

Keep the reusable module interface small; use the official AST and preserve duplicates/positions. Test semantic changes against the pinned actual runtime and verify reports/redaction through the real CLI. Public actions require owner authorization. Preserve licenses and port attribution.
