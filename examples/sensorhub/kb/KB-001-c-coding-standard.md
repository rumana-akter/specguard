+++
id = "KB-001"
title = "C coding standard for SensorHub firmware"
topics = ["coding-standard"]
label = "internal"
+++
Use C11. No dynamic allocation. Use fixed-width integer types. Every
accumulator must be wide enough for the worst case: for N samples of an
int16_t, use an int32_t sum. Check every buffer length before indexing.
Unsigned literals take a `u` suffix. No tabs; lines at most 100 characters.
