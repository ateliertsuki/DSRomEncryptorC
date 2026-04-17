#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "blowfish.h"
#include "blowfish_locator.h"
#include "crc16.h"
#include "key_transform.h"
#include "utils.h"

/* -------------------------------------------------------------------------
 * ROM layout constants (all offsets in bytes)
 * ---------------------------------------------------------------------- */
#define SECURE_AREA_ID                       UINT64_C(0x6A624F7972636E65) /* "encryObj" */

#define ROM_HEADER_GAME_CODE_OFFSET          0x0C
#define ROM_HEADER_UNIT_CODE_OFFSET          0x12
#define ROM_HEADER_TWL_FLAGS_OFFSET          0x1C
#define ROM_HEADER_ARM9_OFFSET_OFFSET        0x20
#define ROM_HEADER_SECURE_AREA_CRC_OFFSET    0x6C
#define ROM_HEADER_NTR_AREA_END_OFFSET       0x90
#define ROM_HEADER_TWL_AREA_START_OFFSET     0x92
#define ROM_HEADER_CRC_OFFSET                0x15E

#define ROM_NTR_BLOWFISH_P_TABLE_OFFSET      0x1600
#define ROM_NTR_BLOWFISH_S_BOXES_OFFSET      0x1C00

#define ROM_SECURE_AREA_START_OFFSET         0x4000
#define ROM_ENCRYPTED_SECURE_AREA_END_OFFSET 0x4800
#define ROM_SECURE_AREA_END_OFFSET           0x8000

#define ROM_TWL_BLOWFISH_P_TABLE_OFFSET      0x0600
#define ROM_TWL_BLOWFISH_S_BOXES_OFFSET      0x0C00

#define TWL_CHUNK_SHIFT                      19
#define TWL_CHUNK_SIZE                       0x80000

#define UNIT_CODE_TWL_FLAG                   0x02
#define TWL_FLAGS_HAS_TWL_EXCLUSIVE_AREA     0x01

/* -------------------------------------------------------------------------
 * File I/O helpers
 * ---------------------------------------------------------------------- */

static uint8_t *read_file(const char *path, size_t *out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Error: Cannot open '%s'\n", path);
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0)                      { fclose(f); return NULL; }
    rewind(f);

    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }

    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f);
        return NULL;
    }
    fclose(f);
    *out_size = (size_t)sz;
    return buf;
}

static bool write_file(const char *path, const uint8_t *data, size_t size)
{
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "Error: Cannot open '%s' for writing\n", path);
        return false;
    }
    bool ok = (fwrite(data, 1, size, f) == size);
    fclose(f);
    return ok;
}

/* -------------------------------------------------------------------------
 * ROM processing helpers
 * ---------------------------------------------------------------------- */

static bool should_have_twl_area(const uint8_t *rom)
{
    return (rom[ROM_HEADER_UNIT_CODE_OFFSET] & UNIT_CODE_TWL_FLAG)       != 0
        && (rom[ROM_HEADER_TWL_FLAGS_OFFSET] & TWL_FLAGS_HAS_TWL_EXCLUSIVE_AREA) != 0;
}

/*
 * Inserts the hardware test patterns into the ROM (mirroring the original
 * C# implementation exactly).
 */
static void insert_test_patterns(uint8_t *rom)
{
    static const uint8_t hdr[8] = { 0xFF, 0x00, 0xFF, 0x00, 0xAA, 0x55, 0xAA, 0x55 };
    memcpy(rom + 0x3000, hdr, 8);

    for (int i = 8; i < 0x200; i++)
        rom[0x3000 + i] = (uint8_t)(i & 0xFF);

    for (int i = 0; i < 0x200; i++)
        rom[0x3200 + i] = (uint8_t)(0xFF - (i & 0xFF));

    memset(rom + 0x3400, 0x00, 0x200);
    memset(rom + 0x3600, 0xFF, 0x200);
    memset(rom + 0x3800, 0x0F, 0x200);
    memset(rom + 0x3A00, 0xF0, 0x200);
    memset(rom + 0x3C00, 0x55, 0x200);
    memset(rom + 0x3E00, 0xAA, 0x1FF);

    rom[0x3FFF] = 0x00;
}

/* -------------------------------------------------------------------------
 * Usage / argument parsing
 * ---------------------------------------------------------------------- */

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "== DSRomEncryptorC by AtelierTsuki ==\n"
        "== Original DSRomEncryptor by Gericom ==\n"
        "\n"
        "Usage: %s [--dsidev] <input.nds> <output.nds>\n"
        "\n"
        "  --dsidev   Use DSi dev blowfish key instead of the retail TWL key.\n"
        "\n"
        "Key files are searched for next to the executable, then in the\n"
        "current working directory:\n"
        "  ntrBlowfish.bin    NTR (DS) blowfish key table  (%zu bytes)\n"
        "  twlBlowfish.bin    TWL (DSi retail) key table   (%zu bytes)\n"
        "  twlDevBlowfish.bin TWL (DSi dev)    key table   (%zu bytes)\n"
        "  biosnds7.rom       DS  ARM7 BIOS dump (0x4000 bytes) [alt for NTR]\n"
        "  biosdsi7.rom       DSi ARM7 BIOS dump (0x10000 bytes) [alt for TWL]\n",
        prog,
        BF_KEY_TABLE_LENGTH,
        BF_KEY_TABLE_LENGTH,
        BF_KEY_TABLE_LENGTH);
}

/* -------------------------------------------------------------------------
 * Main
 * ---------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    const char *input_path  = NULL;
    const char *output_path = NULL;
    bool        use_dsi_dev = false;

    /* Simple argument parsing */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dsidev") == 0) {
            use_dsi_dev = true;
        } else if (!input_path) {
            input_path = argv[i];
        } else if (!output_path) {
            output_path = argv[i];
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!input_path || !output_path) {
        print_usage(argv[0]);
        return 1;
    }

    /* ------------------------------------------------------------------
     * Load NTR blowfish key
     * ------------------------------------------------------------------ */
    uint8_t ntr_blowfish_raw[BF_KEY_TABLE_LENGTH];
    if (!blowfish_locator_get_ntr(ntr_blowfish_raw)) {
        fprintf(stderr, "Error: Could not load ntr blowfish key.\n");
        return 1;
    }

    /* ------------------------------------------------------------------
     * Read ROM
     * ------------------------------------------------------------------ */
    size_t   rom_size;
    uint8_t *rom = read_file(input_path, &rom_size);
    if (!rom)
        return 1;

    /* ------------------------------------------------------------------
     * Derive NTR key table from game code (level 2) and embed it in ROM
     * ------------------------------------------------------------------ */
    uint32_t game_code = read_u32_le(rom + ROM_HEADER_GAME_CODE_OFFSET);

    uint8_t ntr_table[BF_KEY_TABLE_LENGTH];
    key_transform_table(game_code, 2, 8, ntr_blowfish_raw, ntr_table);

    memcpy(rom + ROM_NTR_BLOWFISH_P_TABLE_OFFSET,
           ntr_table,
           BF_KEY_TABLE_P_TABLE_LENGTH);
    memcpy(rom + ROM_NTR_BLOWFISH_S_BOXES_OFFSET,
           ntr_table + BF_KEY_TABLE_P_TABLE_LENGTH,
           BF_KEY_TABLE_S_BOXES_LENGTH);

    /* ------------------------------------------------------------------
     * Insert hardware test patterns
     * ------------------------------------------------------------------ */
    insert_test_patterns(rom);

    /* ------------------------------------------------------------------
     * Encrypt secure area if it hasn't been encrypted yet
     * ------------------------------------------------------------------ */
    uint32_t arm9_offset = read_u32_le(rom + ROM_HEADER_ARM9_OFFSET_OFFSET);
    if (arm9_offset < ROM_SECURE_AREA_END_OFFSET) {
        uint16_t stored_crc = read_u16_le(rom + ROM_HEADER_SECURE_AREA_CRC_OFFSET);
        uint16_t actual_crc = crc16_calculate(rom + arm9_offset,
                                              ROM_SECURE_AREA_END_OFFSET - arm9_offset);
        if (stored_crc != actual_crc) {
            /* Build the "secure" key table (level 3) */
            uint8_t secure_table[BF_KEY_TABLE_LENGTH];
            key_transform_table(game_code, 3, 8, ntr_blowfish_raw, secure_table);

            Blowfish secure_bf, ntr_bf;
            blowfish_init(&secure_bf, secure_table);
            blowfish_init(&ntr_bf,   ntr_table);

            /* Encrypt the 8-byte secure-area ID:
             *   encrypted = ntrBF.Encrypt(secureBF.Encrypt(SECURE_AREA_ID)) */
            uint64_t enc_id = blowfish_encrypt_u64(&secure_bf, SECURE_AREA_ID);
            enc_id          = blowfish_encrypt_u64(&ntr_bf,    enc_id);
            write_u64_le(rom + ROM_SECURE_AREA_START_OFFSET, enc_id);

            /* Encrypt the rest of the encrypted secure area
             * (bytes 0x4008..0x4800) with the secure cipher */
            blowfish_encrypt_bytes(&secure_bf,
                                   rom + ROM_SECURE_AREA_START_OFFSET + 8,
                                   ROM_ENCRYPTED_SECURE_AREA_END_OFFSET
                                       - (ROM_SECURE_AREA_START_OFFSET + 8));

            /* Recalculate and store the secure-area CRC */
            uint16_t new_crc = crc16_calculate(rom + arm9_offset,
                                               ROM_SECURE_AREA_END_OFFSET - arm9_offset);
            write_u16_le(rom + ROM_HEADER_SECURE_AREA_CRC_OFFSET, new_crc);
        }
    }

    /* ------------------------------------------------------------------
     * Handle TWL (DSi) area
     * ------------------------------------------------------------------ */
    if (should_have_twl_area(rom)) {
        uint32_t twl_area_start =
            (uint32_t)read_u16_le(rom + ROM_HEADER_TWL_AREA_START_OFFSET)
            * (uint32_t)TWL_CHUNK_SIZE;

        if (twl_area_start == 0) {
            /* Append a fresh TWL area at the next chunk boundary */
            uint16_t twl_start_value =
                (uint16_t)(((uint32_t)rom_size + (TWL_CHUNK_SIZE - 1))
                            >> TWL_CHUNK_SHIFT);
            twl_area_start = (uint32_t)twl_start_value * TWL_CHUNK_SIZE;

            write_u16_le(rom + ROM_HEADER_NTR_AREA_END_OFFSET,   twl_start_value);
            write_u16_le(rom + ROM_HEADER_TWL_AREA_START_OFFSET, twl_start_value);

            size_t new_size = (size_t)twl_area_start + 0x8000;
            uint8_t *new_rom = (uint8_t *)realloc(rom, new_size);
            if (!new_rom) {
                fprintf(stderr, "Warning: Couldn't insert twl blowfish"
                                " (out of memory).\n");
                goto skip_twl;
            }
            rom = new_rom;
            memset(rom + rom_size, 0, new_size - rom_size);
            rom_size = new_size;
        }

        /* Load the TWL key table */
        uint8_t twl_table[BF_KEY_TABLE_LENGTH];

        if (use_dsi_dev) {
            if (!blowfish_locator_get_twl_dev(twl_table)) {
                fprintf(stderr, "Error: Could not load twl dev blowfish key.\n");
                free(rom);
                return 1;
            }
            /* Dev key is used as-is (no transformation) */
        } else {
            uint8_t twl_blowfish_raw[BF_KEY_TABLE_LENGTH];
            if (!blowfish_locator_get_twl(twl_blowfish_raw)) {
                fprintf(stderr, "Error: Could not load twl blowfish key.\n");
                free(rom);
                return 1;
            }
            key_transform_table(game_code, 1, 8, twl_blowfish_raw, twl_table);
        }

        /* Embed the TWL key table in the ROM's TWL area */
        memcpy(rom + twl_area_start + ROM_TWL_BLOWFISH_P_TABLE_OFFSET,
               twl_table,
               BF_KEY_TABLE_P_TABLE_LENGTH);
        memcpy(rom + twl_area_start + ROM_TWL_BLOWFISH_S_BOXES_OFFSET,
               twl_table + BF_KEY_TABLE_P_TABLE_LENGTH,
               BF_KEY_TABLE_S_BOXES_LENGTH);
    }
skip_twl:;

    /* ------------------------------------------------------------------
     * Fix the ROM header CRC (covers bytes 0x000..0x15D)
     * ------------------------------------------------------------------ */
    uint16_t header_crc = crc16_calculate(rom, ROM_HEADER_CRC_OFFSET);
    write_u16_le(rom + ROM_HEADER_CRC_OFFSET, header_crc);

    /* ------------------------------------------------------------------
     * Write output
     * ------------------------------------------------------------------ */
    if (!write_file(output_path, rom, rom_size)) {
        fprintf(stderr, "Error: Failed to write '%s'\n", output_path);
        free(rom);
        return 1;
    }

    free(rom);
    return 0;
}
