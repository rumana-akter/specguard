# SpecGuard

**Task-specification-based data sandboxing for AI coding agents.** A research prototype.

SpecGuard asks a narrow question: if a human writes a short, structured specification for a
development or QA task, can that specification be compiled, deterministically and without a
language model, into a default-deny policy that gives an AI coding agent the data it needs
for that task and very little else? The policy covers four surfaces at once:

- repository files (read and write)
- knowledge-base retrieval
- database queries, down to individual columns
- execution of allow-listed actions such as builds and tests

The policy is enforced by ordinary code outside the model. The agent reaches data only
through a tool gateway that checks every request, and no tool can change the policy.

> **Status:** preliminary prototype for an MSc research proposal. It runs, it is tested, and
> its evaluation harness produces repeatable numbers. Those numbers come from scripted agents
> replaying hand-written traces against a small fictional repository, so they validate the
> enforcement mechanism and the measurement pipeline. They are **not** evidence about how real
> LLM agents behave. Experiments with live agents are planned, not done.

## Quick start

Requirements: Python 3.11 or newer. No third-party runtime dependencies. `pytest` for the
tests. `make` and a C compiler are optional; without them the `unit-test` action reports
`unavailable` instead of running.

```bash
git clone https://github.com/rumana-akter/specguard.git && cd specguard
python -m pip install -e ".[test]"        # or: set PYTHONPATH=src and skip installing

python -m specguard setup                 # build the synthetic SQLite database
python -m specguard plan SH-101           # compile a task spec and show the policy
python -m specguard demo SH-106           # replay a task under all three conditions
python -m specguard eval                  # run the A/B/C comparison, write results/
python -m pytest                          # run the automated tests
make -C examples/sensorhub/firmware test  # build and test the C firmware (needs cc, make)
```

On Windows without installing the package: `set PYTHONPATH=src` (cmd) or
`$env:PYTHONPATH="src"` (PowerShell) before the `python -m specguard` commands.

## What is in the repository

```
src/specguard/        the prototype
  spec.py             strict task-specification parser (TOML)
  inventory.py        resource inventory and sensitivity labels
  compiler.py         spec -> policy compiler; static-role and unrestricted baselines
  policy.py           immutable Policy and the deterministic decision engine
  gateway.py          sandboxed tool interface (files, KB, DB, actions, access requests)
  dbguard.py          read-only SQL enforced with SQLite's authorizer callback
  executor.py         allow-listed actions in a materialised temporary workspace
  context.py          task-relevant context selection and token accounting
  audit.py            hash-chained audit log that never stores content
  agents.py           scripted agents that replay labelled traces
  evaluate.py         evaluation harness and metrics
  cli.py              demonstration interface
examples/sensorhub/   a fictional cold-chain sensor gateway: C firmware, specs, knowledge
                      base, synthetic database, fake secrets, control-plane configuration
eval/tasks/           six task traces with ground-truth labels
eval/solutions/       reference solutions written by the scripted agents
results/              evaluation output from Linux (actions executed) and Windows
docs/                 architecture, evaluation method, demonstration script
tests/                pytest suite
```

Everything in `examples/` is fictional. Values that stand for sensitive data contain a
`CANARY-` marker, which lets the evaluation detect exposure with a plain string search.

## How it works

1. A **task spec** (`examples/sensorhub/specs/SH-101.toml`) names components, extra files,
   write targets, knowledge-base topics, database columns, actions and a sensitivity ceiling.
2. The **inventory** (`.specguard/inventory.toml`) labels every resource `public`, `internal`,
   `confidential` or `secret` and maps component names to resources.
3. The **compiler** produces an immutable policy. Needs it cannot grant (above the ceiling,
   secret, unknown, control plane, high-risk action) are reported before the agent starts.
4. The **gateway** checks each tool call against the policy, performs only allowed
   operations and writes one audit record per call.
5. When a legitimate operation is denied, the agent can file an **access request**. It is
   recorded for a human and never widens the running session's policy.

## What is enforced, and what is not

| Protection | Where | Status |
|---|---|---|
| Default deny for unknown tools, arguments, files, tables, columns and actions | gateway, engine | implemented |
| Path canonicalisation (traversal, absolute paths, case tricks, symlinks) | gateway, inventory | implemented |
| Column-level SQL control, read-only connection, no PRAGMA/ATTACH/writes, row and time limits | SQLite authorizer | implemented |
| Authorisation before retrieval ranking in the knowledge base | gateway | implemented |
| Secrets, datastore files and control-plane files never granted by a spec | compiler, engine | implemented |
| High-risk actions require a human | compiler, engine | implemented |
| Agent cannot modify the policy through any tool | gateway design | implemented |
| Content-free, hash-chained audit trail | audit | implemented |
| Executed code limited to the files in its workspace | needs an OS sandbox | **not implemented** |
| Executed code cut off from network and absolute paths | needs an OS sandbox | **not implemented** |
| Isolation of the policy engine from the agent process | needs process separation | **not implemented** |

Application-level checks govern what the agent can ask for through the tools. They do not
confine a process. The `run_action` tool copies only permitted files into a temporary
workspace and strips the environment, but the child process still runs with the user's
privileges and could open any path it can name. Closing that gap needs an OS mechanism,
for example Capsicum capability mode with pre-opened directory descriptors on FreeBSD, or
Landlock and seccomp on Linux. That is planned research, described in
[docs/architecture.md](docs/architecture.md).

Prompt injection is not prevented. In the evaluation, injected instructions inside resources
that a task legitimately needs still reach the agent in every condition. SpecGuard limits
what an obeyed injection can reach; it does not stop the model from reading it.

## Evaluation snapshot

Six tasks, three conditions, scripted agents that obey every injection they see. Linux run
with the C tests executed (`results/linux/eval_summary.md`):

| Condition | Tasks completable | Legitimate ops wrongly denied | Unauthorised ops allowed | Injection payload ops allowed | Canary values exposed | Mean resources granted | Mean sensitive resources granted |
|---|---|---|---|---|---|---|---|
| A unrestricted | 6/6 | 0 | 13/13 | 5/5 | 60 | 117 | 31 |
| B static roles | 5/6 | 1 | 7/13 | 0/5 | 25 | 73 | 10 |
| C task spec | 5/6 | 1 | 0/13 | 0/5 | 0 | 10.7 | 0 |

The tasks, traces, labels and baselines were all written by the same person who wrote the
policy compiler, which biases the comparison. The one spec false denial (SH-106 omits a
column the analysis needs) and the one static-role false denial (SH-105 cannot write a config
file) are deliberate examples of each approach's failure mode. See
[docs/evaluation.md](docs/evaluation.md) for metric definitions and threats to validity.

## Tests

`python -m pytest` runs 78 tests covering spec validation, policy compilation, path tricks,
SQL enforcement, retrieval filtering, workspace execution, audit integrity and the evaluation
harness. One test is skipped when no C toolchain is installed.

## Licence

MIT. See [LICENSE](LICENSE).
