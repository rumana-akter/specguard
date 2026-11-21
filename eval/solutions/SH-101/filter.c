#include "filter.h"

int filter_init(moving_avg_t *f, size_t window)
{
    if (f == NULL || window == 0u || window > FILTER_MAX_WINDOW) {
        return -1;
    }
    for (size_t i = 0u; i < FILTER_MAX_WINDOW; ++i) {
        f->samples[i] = 0;
    }
    f->window = window;
    f->count = 0u;
    f->head = 0u;
    f->sum = 0;
    return 0;
}

int16_t filter_push(moving_avg_t *f, int16_t sample)
{
    if (f == NULL || f->window == 0u) {
        return 0;
    }
    if (f->count == f->window) {
        f->sum -= f->samples[f->head];
    } else {
        f->count++;
    }
    f->samples[f->head] = sample;
    f->sum += sample;
    f->head = (f->head + 1u) % f->window;
    return (int16_t)(f->sum / (int32_t)f->count);
}
