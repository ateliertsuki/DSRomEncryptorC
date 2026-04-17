#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <stdint.h>
#include <stddef.h>

#define BF_P_TABLE_ENTRY_COUNT      18
#define BF_S_BOX_COUNT              4
#define BF_S_BOX_ENTRY_COUNT        256
/* 18 * 4 = 72 bytes */
#define BF_KEY_TABLE_P_TABLE_LENGTH (BF_P_TABLE_ENTRY_COUNT * sizeof(uint32_t))
/* 4 * 256 * 4 = 4096 bytes */
#define BF_KEY_TABLE_S_BOXES_LENGTH (BF_S_BOX_COUNT * BF_S_BOX_ENTRY_COUNT * sizeof(uint32_t))
/* 72 + 4096 = 4168 bytes */
#define BF_KEY_TABLE_LENGTH         (BF_KEY_TABLE_P_TABLE_LENGTH + BF_KEY_TABLE_S_BOXES_LENGTH)
#define BF_BLOCK_LENGTH             8

typedef struct {
    uint32_t p_table[BF_P_TABLE_ENTRY_COUNT];
    uint32_t s_boxes[BF_S_BOX_COUNT][BF_S_BOX_ENTRY_COUNT];
} Blowfish;

/*
 * Initialises a Blowfish context from a raw key-table byte buffer.
 * key_table must be at least BF_KEY_TABLE_LENGTH bytes.
 * Layout: P-table at offset 0 (72 bytes LE u32s),
 *         S-box 0 at offset 0x48, S-box 1 at 0x448, S-box 2 at 0x848, S-box 3 at 0xC48.
 */
void blowfish_init(Blowfish *bf, const uint8_t *key_table);

/* Encrypt / decrypt a single 64-bit value. */
uint64_t blowfish_encrypt_u64(const Blowfish *bf, uint64_t val);
uint64_t blowfish_decrypt_u64(const Blowfish *bf, uint64_t val);

/*
 * Encrypt / decrypt a byte buffer in-place.
 * len must be a multiple of BF_BLOCK_LENGTH (8).
 * Values are treated as little-endian 64-bit blocks.
 */
void blowfish_encrypt_bytes(const Blowfish *bf, uint8_t *data, size_t len);
void blowfish_decrypt_bytes(const Blowfish *bf, uint8_t *data, size_t len);

#endif /* BLOWFISH_H */
