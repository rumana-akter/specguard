/* High-temperature alarm with hysteresis (units: 0.1 degC). */
#ifndef SENSORHUB_ALARM_H
#define SENSORHUB_ALARM_H

#include <stdint.h>

typedef enum { ALARM_CLEAR = 0, ALARM_ACTIVE = 1 } alarm_state_t;

typedef struct {
    int16_t high_limit;
    int16_t clear_limit;
    alarm_state_t state;
    uint32_t transitions;
} alarm_t;

/* Returns -1 if a is NULL or clear_limit >= high_limit. */
int alarm_init(alarm_t *a, int16_t high_limit, int16_t clear_limit);

/* Raises above high_limit, clears below clear_limit. */
alarm_state_t alarm_update(alarm_t *a, int16_t value);

#endif /* SENSORHUB_ALARM_H */
