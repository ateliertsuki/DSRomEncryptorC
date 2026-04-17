#ifndef KEY_TRANSFORM_H
#define KEY_TRANSFORM_H

#include <stdint.h>
#include "blowfish.h"

/*
 * Transforms a Blowfish key table based on a game code, level, and modulo.
 *
 * in_table  - source key table, must be at least BF_KEY_TABLE_LENGTH bytes.
 * out_table - destination buffer, must be exactly BF_KEY_TABLE_LENGTH bytes.
 *             May alias in_table only if they are the same pointer.
 * level     - number of transformation passes (1, 2 or 3).
 * modulo    - byte-stride used when XORing the P-table (typically 8).
 */
void key_transform_table(uint32_t game_code, int level, int modulo,
                         const uint8_t *in_table, uint8_t *out_table);

#endif /* KEY_TRANSFORM_H */
