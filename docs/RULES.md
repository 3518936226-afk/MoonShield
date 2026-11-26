# Rules

| Family | Meaning |
|---|---|
| NO_PERMISSION / NO_PERMISSION_HEADER | No explicit embedded policy |
| CONFIG_SYNTAX / INVALID_LITERAL | Official syntax or runtime string conversion failed |
| INVALID_TYPE / UNKNOWN_FIELD | Invalid shape or unknown pinned schema key |
| DUPLICATE_PERMISSION / DUPLICATE_KEY | Ambiguous original/decoded declaration; conservatively rejected even if a runtime overwrites a key |
| FS_BROAD_SCOPE | All paths, root, current/parent scope |
| FS_LITERAL_SCOPE / FS_ABSOLUTE_SCOPE / FS_GLOB_SCOPE | Directory identity/subtree scope not proven |
| ENV_HOST_ALL / ENV_PATH / ENV_LITERAL | Host variables, executable lookup or literal provisioning |
| PROCESS_ALLOW_ALL / PROCESS_UNBOUNDED_ARGS | Arbitrary processes or unbounded argument prefixes |
| PROCESS_INTERPRETER / PROCESS_LOOKUP / PROCESS_HOST_CAPABILITY | Interpreter execution and host capabilities |
| PROCESS_CONFLICT / PROCESS_MODE_CONFLICT | True spawn plus nonempty allow; IPC plus virtualize |
| PROCESS_EXECUTION_MODE | Engine-specific virtual/IPC behavior needs review |
| NETWORK_WILDCARD / NETWORK_ACCESS | Network scope; not live endpoint validation |
| SCAN_INCOMPLETE | Skipped link/target or no matching inputs |

TOML/legacy YAML/JSON null special cases are explicitly unimplemented. Static findings are not a runtime authorization oracle. A deny-all permission() can have no findings without proving its body valid or trustworthy. --fail-on changes only exit thresholds, not reported findings.

Schema v2 reports unimplemented coverage as UNSUPPORTED, distinct from INVALID. Both always block. Original configuration findings remain intact; supported trivial direct-denial context and optional regular-file metadata observations can downgrade projected risk to information. Details and limitations: AUDIT_SEMANTICS.md.
