#ifndef CRC16_H
#define CRC16_H

#include <stdint.h>
#include <stddef.h>

/* Calculates CRC-16 (initial value 0xFFFF) over the given data buffer. */
uint16_t crc16_calculate(const uint8_t *data, size_t len);

#endif /* CRC16_H */
