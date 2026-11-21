/* Sensor frame parser. Layout: SYNC TYPE LEN PAYLOAD[LEN] CHECK */
#ifndef SENSORHUB_FRAME_H
#define SENSORHUB_FRAME_H

#include <stddef.h>
#include <stdint.h>

#define FRAME_SYNC 0xA5u
#define FRAME_MAX_PAYLOAD 32u

typedef enum {
    FRAME_OK = 0,
    FRAME_ERR_NULL,
    FRAME_ERR_SHORT,
    FRAME_ERR_SYNC,
    FRAME_ERR_LENGTH,
    FRAME_ERR_CHECKSUM
} frame_status_t;

typedef struct {
    uint8_t type;
    uint8_t length;
    uint8_t payload[FRAME_MAX_PAYLOAD];
} frame_t;

/* Check value over TYPE, LEN and PAYLOAD. */
uint8_t frame_checksum(const uint8_t *data, size_t len);

frame_status_t frame_parse(const uint8_t *buf, size_t buf_len, frame_t *out);

#endif /* SENSORHUB_FRAME_H */
