# Device configuration reference

| Key | Default | Meaning |
|---|---|---|
| `sensor.filter_window` | 16 | Moving-average window in samples (1 to 64) |
| `sensor.temperature_unit` | `decidegree_c` | Unit of reported temperatures |
| `sensor.sample_period_ms` | 1000 | Milliseconds between sensor samples |
| `alarm.high_limit` | 80 | Alarm raises above this value |
| `alarm.clear_limit` | 75 | Alarm clears below this value |
| `uplink.retry_backoff_s` | 30 | Seconds between upload retries |
