# SpecGuard prototype architecture

## 1. Components and trust

```
 TRUSTED (written and reviewed by people)          UNTRUSTED
 ------------------------------------------        ------------------------------------
 task spec (specs/SH-101.toml)                     language model and its outputs
 inventory + labels (.specguard/inventory.toml)    tool arguments chosen by the model
 action allow-list (.specguard/actions.toml)       repository contents (may hold injections)
 static roles (.specguard/static_roles.toml)       knowledge-base text, database rows
 SpecGuard code, OS                                command output

        spec + inventory
              |
              v
     +------------------+   frozen Policy (sha256 digest)
     |  policy compiler |---------------------------+
     +------------------+                           |
              | exclusions, warnings (shown         v
              | to the human before the run)  +-----------+
                                              |  policy   |
  agent --- tool call (name, args) --------> |  engine   |
    ^          |                              +-----------+
    |          v                                    ^
    |   +--------------+  allowed?  ----------------+
    |   | tool gateway |
    |   +--------------+--> files (overlay for writes)
    |          |        --> knowledge base (filter, then rank)
    |          |        --> SQLite (read-only, authorizer callback)
    |          |        --> executor (temporary workspace, fixed argv)
    |          |        --> access-request queue (never auto-granted)
    |          v
    |     audit log (decisions only, hash chain)
    +---- result (content only if allowed)
```

The model never sees the policy object, the inventory or the audit log, and no tool takes a
policy as an argument. A policy is compiled once per session. Widening scope means a person
edits and approves the spec, and a new session starts with a new policy digest.

## 2. Modules

| Module | Responsibility | Key design choice |
|---|---|---|
| `spec.py` | Parse and validate task specs | Unknown keys are errors; `secret` ceilings and unsafe paths are rejected at parse time |
| `inventory.py` | Enumerate files, KB articles, tables, columns, components, actions; attach labels | Unlisted files default to `confidential`; symlinks are never inventoried; column labels can only raise a table's label |
| `compiler.py` | Spec to `Policy`; static roles; unrestricted baseline | Pure function of spec and inventory; every refused need becomes an `Exclusion` with a reason |
| `policy.py` | `Policy` dataclass and `PolicyEngine` decisions | Invariants (ceiling, control plane, datastores, protected writes, high-risk actions) are checked before grants, so a broad pattern cannot override them |
| `gateway.py` | The only interface the agent sees | Argument allow-lists per tool; canonical path lookup; writes go to an in-memory overlay; listings show only permitted entries |
| `dbguard.py` | SQL access | SQLite authorizer decides every column read, function call and operation during statement compilation; read-only URI; progress-handler time limit; row cap |
| `executor.py` | Allow-listed actions | Fixed argv, no shell, minimal environment, timeout, output truncation; workspace holds only declared inputs under the ceiling plus the agent's writes |
| `context.py` | Context selection and token accounting | Ranks only resources the policy already permits, then fills the spec's token budget |
| `audit.py` | Audit trail | Field allow-list; SQL stored as a fingerprint plus columns touched; free text stored as length only; SHA-256 hash chain |
| `agents.py`, `evaluate.py` | Scripted agents and metrics | Deterministic replay of labelled traces; canary search for exposure |

## 3. Decision order in the engine

For a file request the engine applies, in order:

1. unknown path: deny (`DENY_UNKNOWN_RESOURCE`)
2. control-plane path: deny (`DENY_CONTROL_PLANE`)
3. datastore file (the raw `.db`): deny (`DENY_DATASTORE_DIRECT`); data is reachable only through `query_db`
4. write to a protected path (`specs/`, `kb/`, `tools/`): deny (`DENY_PROTECTED_WRITE`)
5. label above the policy ceiling: deny (`DENY_ABOVE_CEILING`)
6. path matches a grant: allow
7. otherwise: deny (`DENY_NOT_GRANTED`)

Steps 2 to 5 are skipped only for the unrestricted baseline. Knowledge-base articles,
database columns and actions follow the same pattern.

## 4. Missing permissions

Missing permissions are handled at two points:

- **Before the run.** `python -m specguard plan SH-104` lists needs the compiler refused,
  for example `kb:KB-005: ABOVE_CEILING`. A spec author can fix the spec or accept the gap.
- **During the run.** A denied call returns a reason code. The agent can call
  `request_access`, which records a structured request for a person and returns a message
  explaining that the session's policy will not change.

## 5. What would need an OS sandbox

| Gap | Why application checks are not enough | Candidate mechanism |
|---|---|---|
| Code run by `run_action` can open absolute paths, including the original repository and `secrets/` | The child process inherits the user's file-system authority | Capsicum: open the workspace directory, `cap_rights_limit` it, `cap_enter`, then exec; or Landlock rulesets on Linux |
| Executed code can use the network | Nothing in the executor blocks sockets | Capsicum capability mode (no global namespaces); seccomp or network namespaces on Linux |
| Policy engine shares a process with the harness | In-process immutability can be bypassed by code in the same interpreter | Run the gateway as a separate process (for example an MCP server) with the agent confined |
| Output of executed code is a side channel | Tests can print any file in their workspace | Keep sensitive files out of the workspace (implemented) and confine the process (planned) |

The thesis work would compile the execution part of a policy into a capability set, so that
the same spec drives both the tool-level checks and the OS-level confinement.
