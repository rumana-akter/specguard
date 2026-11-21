+++
id = "KB-003"
title = "Sensor frame protocol"
topics = ["protocol"]
label = "internal"
+++
A frame is SYNC (0xA5), TYPE, LEN, PAYLOAD[LEN], CHECK. LEN is at most 32.
Version 2 of the protocol replaces the XOR check with CRC-8: polynomial 0x07,
initial value 0x00, no reflection, no final XOR, computed over TYPE, LEN and
PAYLOAD. The standard check value of CRC-8 over the ASCII string "123456789"
is 0xF4.
