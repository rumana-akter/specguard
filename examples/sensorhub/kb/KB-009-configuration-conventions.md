+++
id = "KB-009"
title = "Device configuration conventions"
topics = ["configuration"]
label = "internal"
+++
Configuration keys use snake_case and include their unit in the name when the
unit is not obvious (for example `retry_backoff_s`, `sample_period_ms`). Every
key in config/device_config.toml must be documented in
docs/config_reference.md with its default and meaning.
