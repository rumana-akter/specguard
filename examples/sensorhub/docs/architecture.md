# SensorHub architecture (fictional)

A gateway reads temperature and humidity sensors over a serial bus. Each
reading arrives as a frame (`firmware/src/frame.c`), is smoothed by a moving
average (`firmware/src/filter.c`) and is checked against alarm limits with
hysteresis (`firmware/src/alarm.c`). Readings and alarm events are uploaded
to a back end, where they are stored in the operations database.

The firmware is written in C11 without dynamic allocation. Units are tenths of
a degree Celsius throughout.
