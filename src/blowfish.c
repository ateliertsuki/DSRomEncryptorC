#include "blowfish.h"
#include "utils.h"

#include <assert.h>

void blowfish_init(Blowfish *bf, const uint8_t *key_table)
{
    /* P-table: 18 little-endian uint32s starting at offset 0 */
    for (int i = 0; i < BF_P_TABLE_ENTRY_COUNT; i++)
        bf->p_table[i] = read_u32_le(key_table + i * 4);

    /*
     * S-boxes: each box is 256 little-endian uint32s.
     * S-box 0 starts at offset 0x48 (= BF_KEY_TABLE_P_TABLE_LENGTH).
     * Subsequent boxes are each 0x400 (1024) bytes apart.
     */
    for (int s = 0; s < BF_S_BOX_COUNT; s++) {
        const uint8_t *src = key_table + 0x48 + s * (BF_S_BOX_ENTRY_COUNT * 4);
        for (int j = 0; j < BF_S_BOX_ENTRY_COUNT; j++)
            bf->s_boxes[s][j] = read_u32_le(src + j * 4);
    }
}

uint64_t blowfish_encrypt_u64(const Blowfish *bf, uint64_t val)
{
    uint32_t y = (uint32_t)(val & 0xFFFFFFFFu);
    uint32_t x = (uint32_t)(val >> 32);

    for (int i = 0; i < 16; i++) {
        uint32_t z = bf->p_table[i] ^ x;
        uint32_t a = bf->s_boxes[0][(z >> 24) & 0xFF];
        uint32_t b = bf->s_boxes[1][(z >> 16) & 0xFF];
        uint32_t c = bf->s_boxes[2][(z >>  8) & 0xFF];
        uint32_t d = bf->s_boxes[3][ z        & 0xFF];
        x = d + (c ^ (b + a)) ^ y;
        y = z;
    }

    return (uint64_t)(x ^ bf->p_table[16])
         | ((uint64_t)(y ^ bf->p_table[17]) << 32);
}

uint64_t blowfish_decrypt_u64(const Blowfish *bf, uint64_t val)
{
    uint32_t y = (uint32_t)(val & 0xFFFFFFFFu);
    uint32_t x = (uint32_t)(val >> 32);

    for (int i = 17; i >= 2; i--) {
        uint32_t z = bf->p_table[i] ^ x;
        uint32_t a = bf->s_boxes[0][(z >> 24) & 0xFF];
        uint32_t b = bf->s_boxes[1][(z >> 16) & 0xFF];
        uint32_t c = bf->s_boxes[2][(z >>  8) & 0xFF];
        uint32_t d = bf->s_boxes[3][ z        & 0xFF];
        x = d + (c ^ (b + a)) ^ y;
        y = z;
    }

    return (uint64_t)(x ^ bf->p_table[1])
         | ((uint64_t)(y ^ bf->p_table[0]) << 32);
}

void blowfish_encrypt_bytes(const Blowfish *bf, uint8_t *data, size_t len)
{
    assert((len & 7) == 0 && "data length must be a multiple of 8");
    for (size_t i = 0; i < len; i += BF_BLOCK_LENGTH) {
        uint64_t val = read_u64_le(data + i);
        write_u64_le(data + i, blowfish_encrypt_u64(bf, val));
    }
}

void blowfish_decrypt_bytes(const Blowfish *bf, uint8_t *data, size_t len)
{
    assert((len & 7) == 0 && "data length must be a multiple of 8");
    for (size_t i = 0; i < len; i += BF_BLOCK_LENGTH) {
        uint64_t val = read_u64_le(data + i);
        write_u64_le(data + i, blowfish_decrypt_u64(bf, val));
    }
}
