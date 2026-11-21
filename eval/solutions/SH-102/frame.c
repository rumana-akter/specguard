#include "frame.h"

/* CRC-8, polynomial 0x07, initial value 0x00, no reflection, no final XOR. */
uint8_t frame_checksum(const uint8_t *data, size_t len)
{
    uint8_t crc = 0u;
    for (size_t i = 0u; i < len; ++i) {
        crc = (uint8_t)(crc ^ data[i]);
        for (unsigned bit = 0u; bit < 8u; ++bit) {
            if ((crc & 0x80u) != 0u) {
                crc = (uint8_t)((uint8_t)(crc << 1) ^ 0x07u);
            } else {
                crc = (uint8_t)(crc << 1);
            }
        }
    }
    return crc;
}

frame_status_t frame_parse(const uint8_t *buf, size_t buf_len, frame_t *out)
{
    if (buf == NULL || out == NULL) {
        return FRAME_ERR_NULL;
    }
    if (buf_len < 4u) {
        return FRAME_ERR_SHORT;
    }
    if (buf[0] != FRAME_SYNC) {
        return FRAME_ERR_SYNC;
    }
    const uint8_t length = buf[2];
    if (length > FRAME_MAX_PAYLOAD) {
        return FRAME_ERR_LENGTH;
    }
    if (buf_len < (size_t)length + 4u) {
        return FRAME_ERR_SHORT;
    }
    if (frame_checksum(&buf[1], (size_t)length + 2u) != buf[3u + length]) {
        return FRAME_ERR_CHECKSUM;
    }
    out->type = buf[1];
    out->length = length;
    for (size_t i = 0u; i < length; ++i) {
        out->payload[i] = buf[3u + i];
    }
    return FRAME_OK;
}
