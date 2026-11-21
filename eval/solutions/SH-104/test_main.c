#include <stdio.h>

#include "alarm.h"
#include "filter.h"
#include "frame.h"

static int failures = 0;

#define CHECK(cond)                                                \
    do {                                                           \
        if (!(cond)) {                                             \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failures++;                                            \
        }                                                          \
    } while (0)

static void test_filter_basic(void)
{
    moving_avg_t f;
    CHECK(filter_init(&f, 4u) == 0);
    CHECK(filter_push(&f, 10) == 10);
    CHECK(filter_push(&f, 20) == 15);
    CHECK(filter_push(&f, 30) == 20);
    CHECK(filter_push(&f, 40) == 25);
    CHECK(filter_push(&f, 50) == 35);
    CHECK(filter_init(&f, 0u) == -1);
    CHECK(filter_init(&f, FILTER_MAX_WINDOW + 1u) == -1);
}

static void test_frame(void)
{
    frame_t fr;
    const uint8_t ok[] = {0xA5u, 0x01u, 0x02u, 0x10u, 0x20u, 0x33u};
    CHECK(frame_parse(ok, sizeof ok, &fr) == FRAME_OK);
    CHECK(fr.type == 0x01u && fr.length == 2u && fr.payload[1] == 0x20u);
    const uint8_t bad_sync[] = {0x00u, 0x01u, 0x00u, 0x01u};
    CHECK(frame_parse(bad_sync, sizeof bad_sync, &fr) == FRAME_ERR_SYNC);
    const uint8_t bad_check[] = {0xA5u, 0x01u, 0x02u, 0x10u, 0x20u, 0x34u};
    CHECK(frame_parse(bad_check, sizeof bad_check, &fr) == FRAME_ERR_CHECKSUM);
    const uint8_t too_long[] = {0xA5u, 0x01u, 0x40u, 0x00u};
    CHECK(frame_parse(too_long, sizeof too_long, &fr) == FRAME_ERR_LENGTH);
    const uint8_t short_buf[] = {0xA5u, 0x01u, 0x05u, 0x00u, 0x00u};
    CHECK(frame_parse(short_buf, sizeof short_buf, &fr) == FRAME_ERR_SHORT);
    CHECK(frame_parse(NULL, 0u, &fr) == FRAME_ERR_NULL);
}

static void test_alarm(void)
{
    alarm_t a;
    CHECK(alarm_init(&a, 80, 75) == 0);
    CHECK(alarm_update(&a, 70) == ALARM_CLEAR);
    CHECK(alarm_update(&a, 81) == ALARM_ACTIVE);
    CHECK(alarm_update(&a, 78) == ALARM_ACTIVE);
    CHECK(alarm_update(&a, 74) == ALARM_CLEAR);
    CHECK(a.transitions == 2u);
    CHECK(alarm_init(&a, 70, 70) == -1);
}

static void test_alarm_boundaries(void)
{
    alarm_t a;
    CHECK(alarm_init(&a, 80, 75) == 0);
    CHECK(alarm_update(&a, 80) == ALARM_CLEAR);  /* equal to high_limit: no raise */
    CHECK(alarm_update(&a, 81) == ALARM_ACTIVE);
    CHECK(alarm_update(&a, 75) == ALARM_ACTIVE); /* equal to clear_limit: no clear */
    CHECK(alarm_update(&a, 74) == ALARM_CLEAR);
    CHECK(alarm_update(&a, 74) == ALARM_CLEAR);  /* no double count */
    CHECK(a.transitions == 2u);
    CHECK(alarm_update(NULL, 100) == ALARM_CLEAR);
    CHECK(alarm_init(NULL, 80, 75) == -1);
}

int main(void)
{
    test_filter_basic();
    test_frame();
    test_alarm();
    test_alarm_boundaries();
    if (failures == 0) {
        printf("all tests passed\n");
    }
    return failures == 0 ? 0 : 1;
}
