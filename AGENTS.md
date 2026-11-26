# MoonShield engineering instructions

Keep new development, downloads, builds, configurable caches and evidence in D/project-local directories. Preserve previous phase evidence and unrelated projects. Never expose real secrets in fixtures or run candidate bodies while auditing.

Business logic belongs in MoonBit src/cmd modules. Do not implement a competing parser with regular expressions. Keep upstream vendor bytes immutable; apply the documented generator-manifest adaptation only in work/parser-build. Do not read the large generated tokens.mbt; inspect parser.mbty or interfaces.

Run scripts/test.ps1 and the CLI acceptance suite after material changes. Required runtime probes must execute real Moonrun Wasm at least three times and retain argv/cwd/exit/stdout/stderr. Native helpers cannot stand in for permission isolation. Unknown or unstable critical behavior is NO-GO.

Do not install unnecessary dependencies, silently update version hashes, clean old evidence, or publish/commit/push/register without the owner's explicit authorization. Keep source attribution and licensing complete.
