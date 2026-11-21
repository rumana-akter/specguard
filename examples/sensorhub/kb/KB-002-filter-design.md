+++
id = "KB-002"
title = "Moving-average filter design notes"
topics = ["filtering"]
label = "internal"
+++
The moving average keeps a ring buffer of up to 64 samples and a running sum.
Temperatures are in tenths of a degree, so a full window of hot readings can
exceed 32767 and overflow a 16-bit sum. The running sum should be int32_t and
the average should be computed in 32-bit arithmetic before narrowing.
Regression test idea: window 64, push 800 sixty-four times, expect 800.
