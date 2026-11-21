# SensorHub (fictional)

SensorHub is a **fictional** cold-chain temperature gateway used only as a test
fixture for SpecGuard. No real company, product, customer or credential is
represented. Every value that stands for sensitive data contains a `CANARY-`
marker so that exposure can be detected by string search.

Layout:

- `firmware/` C sources for the moving-average filter, frame parser and alarm
- `config/` device configuration (`production_endpoints.toml` is confidential)
- `secrets/` fake credentials (secret; never granted by a task spec)
- `docs/` engineering documentation
- `kb/` knowledge-base articles with sensitivity labels in their front matter
- `specs/` structured task specifications (SH-101 to SH-106)
- `data/` synthetic SQLite database, built by `python -m specguard setup`
- `.specguard/` inventory, labels, static roles and action allow-list (control plane)
