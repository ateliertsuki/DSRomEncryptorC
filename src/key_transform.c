#include "key_transform.h"
#include "utils.h"

#include <string.h>

/*
 * Applies one key-code transformation pass to key_table.
 *
 * The pass consists of three steps:
 *   1. Encrypt key_code[4..12] in-place with the current table.
 *   2. Encrypt key_code[0..8]  in-place with the current table.
 *   3. XOR each P-table entry with the big-endian uint32 from key_code at
 *      offset (i * 4 % modulo).
 *   4. Re-encrypt the entire key_table block by block (8 bytes at a time),
 *      re-initialising the cipher from the updated table before each block.
 *      The two 4-byte halves of the encrypted scratch value are written to
 *      the table in swapped order.
 */
static void apply_key_code(uint8_t *key_code, int modulo, uint8_t *key_table)
{
    Blowfish bf;
    blowfish_init(&bf, key_table);

    /* Steps 1 & 2 */
    blowfish_encrypt_bytes(&bf, key_code + 4, 8);
    blowfish_encrypt_bytes(&bf, key_code,     8);

    /* Step 3: XOR P-table entries with big-endian words from key_code */
    for (int i = 0; i < BF_P_TABLE_ENTRY_COUNT; i++) {
        uint32_t kt_val = read_u32_le(key_table + i * 4);
        uint32_t kc_val = read_u32_be(key_code + (i * 4 % modulo));
        write_u32_le(key_table + i * 4, kt_val ^ kc_val);
    }

    /*
     * Step 4: iterate over every 8-byte block of the table and replace it
     * with an encrypted zero-block, re-keying from the updated table each
     * iteration.  Note that the two 32-bit halves are stored in reverse
     * order: scratch[4..8] goes to table[i..i+4] and scratch[0..4] goes to
     * table[i+4..i+8].
     */
    uint8_t scratch[8] = {0};
    for (size_t i = 0; i < BF_KEY_TABLE_LENGTH; i += BF_BLOCK_LENGTH) {
        blowfish_init(&bf, key_table);
        blowfish_encrypt_bytes(&bf, scratch, 8);
        memcpy(key_table + i,     scratch + 4, 4);
        memcpy(key_table + i + 4, scratch,     4);
    }
}

void key_transform_table(uint32_t game_code, int level, int modulo,
                         const uint8_t *in_table, uint8_t *out_table)
{
    memcpy(out_table, in_table, BF_KEY_TABLE_LENGTH);

    /*
     * Build the 12-byte key code:
     *   [0..4]  = gameCode
     *   [4..8]  = gameCode >> 1
     *   [8..12] = gameCode << 1
     */
    uint8_t key_code[12];
    write_u32_le(key_code,      game_code);
    write_u32_le(key_code + 4,  game_code >> 1);
    write_u32_le(key_code + 8,  game_code << 1);

    if (level >= 1) apply_key_code(key_code, modulo, out_table);
    if (level >= 2) apply_key_code(key_code, modulo, out_table);

    /* Mutate key_code before the optional third pass */
    uint32_t kc4 = read_u32_le(key_code + 4);
    uint32_t kc8 = read_u32_le(key_code + 8);
    write_u32_le(key_code + 4, kc4 << 1);
    write_u32_le(key_code + 8, kc8 >> 1);

    if (level >= 3) apply_key_code(key_code, modulo, out_table);
}
