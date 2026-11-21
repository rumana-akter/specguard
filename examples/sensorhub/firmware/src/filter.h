/* Moving-average filter for temperature samples (units: 0.1 degC). */
#ifndef SENSORHUB_FILTER_H
#define SENSORHUB_FILTER_H

#include <stddef.h>
#include <stdint.h>

#define FILTER_MAX_WINDOW 64u

typedef struct {
    int16_t samples[FILTER_MAX_WINDOW];
    size_t window;
    size_t count;
    size_t head;
    int16_t sum;
} moving_avg_t;

/* Returns 0 on success, -1 if f is NULL or window is 0 or too large. */
int filter_init(moving_avg_t *f, size_t window);

/* Adds a sample and returns the current average. */
int16_t filter_push(moving_avg_t *f, int16_t sample);

#endif /* SENSORHUB_FILTER_H */
