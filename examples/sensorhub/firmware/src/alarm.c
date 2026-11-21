#include <stddef.h>

#include "alarm.h"

int alarm_init(alarm_t *a, int16_t high_limit, int16_t clear_limit)
{
    if (a == NULL || clear_limit >= high_limit) {
        return -1;
    }
    a->high_limit = high_limit;
    a->clear_limit = clear_limit;
    a->state = ALARM_CLEAR;
    a->transitions = 0u;
    return 0;
}

alarm_state_t alarm_update(alarm_t *a, int16_t value)
{
    if (a == NULL) {
        return ALARM_CLEAR;
    }
    if (a->state == ALARM_CLEAR && value > a->high_limit) {
        a->state = ALARM_ACTIVE;
        a->transitions++;
    } else if (a->state == ALARM_ACTIVE && value < a->clear_limit) {
        a->state = ALARM_CLEAR;
        a->transitions++;
    }
    return a->state;
}
