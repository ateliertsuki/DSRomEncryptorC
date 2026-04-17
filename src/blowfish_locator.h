#ifndef BLOWFISH_LOCATOR_H
#define BLOWFISH_LOCATOR_H

#include <stdbool.h>
#include <stdint.h>
#include "blowfish.h"

/*
 * Each function tries to load a key table from a file adjacent to the
 * executable (or the current working directory as fallback).
 *
 * Lookup order for each key:
 *
 *   NTR  -> ntrBlowfish.bin  (BF_KEY_TABLE_LENGTH bytes)
 *         -> biosnds7.rom    (0x4000 bytes; key extracted at offset 0x30)
 *
 *   TWL  -> twlBlowfish.bin  (BF_KEY_TABLE_LENGTH bytes)
 *         -> biosdsi7.rom    (0x10000 bytes; key extracted at offset 0xC6D0)
 *
 *   TWL-dev -> twlDevBlowfish.bin  (BF_KEY_TABLE_LENGTH bytes, used verbatim)
 *
 * out_table must point to a buffer of at least BF_KEY_TABLE_LENGTH bytes.
 * Returns true on success.
 */
bool blowfish_locator_get_ntr(uint8_t *out_table);
bool blowfish_locator_get_twl(uint8_t *out_table);
bool blowfish_locator_get_twl_dev(uint8_t *out_table);

#endif /* BLOWFISH_LOCATOR_H */
