# Threat model

Goal: detect accidentally broad/ambiguous permissions and runtime permission regressions. audit never compiles or executes a candidate body or downloads its imports. Malformed input must not become an empty deny policy.

Trusted: MoonShield source/artifact, user-selected lockfiles, pinned tools, OS and output location. Lockfiles are local trust inputs, not signatures. A racing owner of the workspace can replace them; no adversarial integrity root is claimed.

Untrusted data: configuration text and filenames. Text goes to the official parser, not to MoonBit, PowerShell or shell evaluation. Runtime probes inherit no ambient secrets: only synthetic values, public SystemRoot metadata and explicit project-local temporary paths are supplied.

Out of scope: arbitrary unsafe execution, native-child sandboxing, containers/identity isolation, CPU/memory quotas, helper-tree termination, malicious build dependencies, data-flow proofs, full network validation, ambient-session discovery, every alias/race and untested OSes. Network conformance probes make no external connections.

Unsupported inputs, unknown keys, no policy and incomplete scans cannot silently pass. Compiler/fixture failures cannot count as permission-denial success. Denial assertions require actual Sandbox policy blocked diagnostics; invalid-policy assertions require policy/front-matter diagnostics. Write probes check real postconditions. Each runtime scenario repeats at least three times.

env.set values are redacted; other paths/arguments/names may appear. Raw test evidence contains synthetic fixtures. Review private-input logs before publication.

Schema-v2 contextual reductions only prove trivial empty-rule direct denials and preserve raw configuration risk. They never approximate arbitrary intersections or infer real session ceilings. Optional inspect reads metadata, not candidate data; canonical equality is a snapshot, not hardlink or race-free proof. See AUDIT_SEMANTICS.md.
