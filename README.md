# SpecGuard

A small research prototype that limits what an AI coding agent can access, based on a
task specification.

Each task has a short spec file that says which parts of the project the task touches.
SpecGuard turns that spec into access rules and checks every request the agent makes:
file reads and writes, knowledge-base lookups, database queries (down to column level)
and build or test commands. Anything not covered by the spec is denied.

The example project in `examples/sensorhub` is fictional. It has C sensor firmware, a
SQLite database with synthetic data, a few knowledge-base articles and some fake secrets.

## Running it

Python 3.11 or newer. No other dependencies apart from `pytest` for the tests.

```bash
git clone https://github.com/rumana-akter/specguard.git
cd specguard
pip install -e ".[test]"

python -m specguard setup          # create the sample database
python -m specguard plan SH-101    # show the rules generated from a task spec
python -m specguard demo SH-106    # run one task with and without restrictions
python -m specguard eval           # compare all tasks, results go to results/
python -m pytest
```

`make` and a C compiler are needed only to run the firmware tests
(`make -C examples/sensorhub/firmware test`).

## Layout

```
src/specguard/       the prototype
examples/sensorhub/  fictional project, task specs and resource labels
eval/                task scripts used for the comparison
results/             saved comparison results
tests/               tests
docs/                architecture and evaluation notes
```

## Notes

The comparison uses scripted agents that replay fixed steps, not real AI models, so the
results only show that the access rules work as intended. The checks also run at the tool
level only: commands the agent runs are not isolated by the operating system yet.

## Licence

MIT
