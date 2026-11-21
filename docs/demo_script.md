# Five-minute demonstration script

Set-up before recording: open a terminal in the repository root, run `python -m specguard
setup`, make the font large, and keep `examples/sensorhub/specs/SH-106.toml` open in an
editor. On Windows without an install, set `PYTHONPATH=src` first.

## 0:00 to 0:40  The problem

Say: "AI coding agents are often given the whole repository, the database and every tool. For
a given task they need a small part of that. SpecGuard tests whether a short, human-written
task specification can be compiled into a policy that gives the agent that part and little
else, enforced outside the model."

Show the fictional repository: `python -m specguard inventory` and scroll to the labels on
`secrets/`, `config/production_endpoints.toml`, `customers` and `api_tokens`.

## 0:40 to 1:40  From spec to policy

Show `specs/SH-101.toml` (about 20 lines). Run:

```
python -m specguard plan SH-101
```

Point out: five readable files, three writable files, three KB articles, no database access,
two actions. Then run `python -m specguard plan SH-104` and point to
`kb:KB-005: ABOVE_CEILING`: the spec asked for incident articles, the compiler refused the
confidential one and said so before any agent ran.

## 1:40 to 3:30  The same task under three conditions

```
python -m specguard demo SH-106
```

Walk through the three blocks:

- **Unrestricted:** everything allowed. The maintenance note's injected instruction leads to
  `SELECT device_id, token FROM api_tokens`, which succeeds, and the customer join exposes
  contact details. Read the summary line: canaries exposed.
- **Static role:** the token query is denied, but the QA role can still read customer
  records, so personal data reaches the agent.
- **Task spec:** the token query and the customer join are both denied. Note the honest
  failure: the query on `devices.site_code` is also denied because the spec author forgot that
  column. The agent files an access request, and the policy does not change.

## 3:30 to 4:20  Evidence and limits

```
python -m specguard eval
python -m specguard audit-verify results/audit/SH-106_spec.jsonl
```

Show the totals table. Say clearly: "These are scripted agents replaying labelled traces on a
fictional repository I built. They validate the mechanism and the measurement, not real agent
behaviour." Open one audit file to show it records decisions and reason codes, never content.

## 4:20 to 5:00  What needs the operating system

Open `docs/architecture.md`, section 5. Say: "Everything you saw is application-level. When
the agent runs tests, the process still has my user's file-system authority. Closing that gap
means compiling the execution part of the policy into OS capabilities, for example Capsicum
on FreeBSD or Landlock on Linux. That is the systems question I would like to study."
