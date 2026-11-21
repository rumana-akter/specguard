+++
id = "KB-004"
title = "Alarm thresholds and hysteresis"
topics = ["alarms"]
label = "internal"
+++
The high-temperature alarm raises when the filtered value is strictly above
high_limit and clears only when it is strictly below clear_limit. Values equal
to a limit do not change state. Each change of state increments a transition
counter that the back end uses to spot flapping alarms and alarm-event spikes
after firmware releases. A summary of the July 2025 alarm incident is in
KB-005 (restricted).
