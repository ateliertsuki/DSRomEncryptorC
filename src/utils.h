#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

static inline uint16_t read_u16_le(const uint8_t *p)
{
    return (uint16_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8));
}

static inline void write_u16_le(uint8_t *p, uint16_t val)
{
    p[0] = (uint8_t)(val);
    p[1] = (uint8_t)(val >> 8);
}

static inline uint32_t read_u32_le(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static inline void write_u32_le(uint8_t *p, uint32_t val)
{
    p[0] = (uint8_t)(val);
    p[1] = (uint8_t)(val >> 8);
    p[2] = (uint8_t)(val >> 16);
    p[3] = (uint8_t)(val >> 24);
}

static inline uint32_t read_u32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)
         | (uint32_t)p[3];
}

static inline uint64_t read_u64_le(const uint8_t *p)
{
    return (uint64_t)read_u32_le(p) | ((uint64_t)read_u32_le(p + 4) << 32);
}

static inline void write_u64_le(uint8_t *p, uint64_t val)
{
    p[0] = (uint8_t)(val);
    p[1] = (uint8_t)(val >> 8);
    p[2] = (uint8_t)(val >> 16);
    p[3] = (uint8_t)(val >> 24);
    p[4] = (uint8_t)(val >> 32);
    p[5] = (uint8_t)(val >> 40);
    p[6] = (uint8_t)(val >> 48);
    p[7] = (uint8_t)(val >> 56);
}

#endif /* UTILS_H */
