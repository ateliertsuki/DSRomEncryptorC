#include "blowfish_locator.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#  include <windows.h>
#elif defined(__linux__)
#  include <unistd.h>
#elif defined(__APPLE__)
#  include <mach-o/dyld.h>
#  include <stdint.h>
#endif

#define NTR_BLOWFISH_NAME    "ntrBlowfish.bin"
#define TWL_BLOWFISH_NAME    "twlBlowfish.bin"
#define TWL_DEV_BLOWFISH_NAME "twlDevBlowfish.bin"
#define BIOS_NDS7_NAME       "biosnds7.rom"
#define BIOS_DSI7_NAME       "biosdsi7.rom"

#define BIOS_NDS7_LENGTH          0x4000
#define BIOS_NDS7_BLOWFISH_OFFSET 0x30
#define BIOS_DSI7_LENGTH          0x10000
#define BIOS_DSI7_BLOWFISH_OFFSET 0xC6D0

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/*
 * Fills exe_dir (capacity cap) with the directory that contains the running
 * executable.  Returns 0 on success, -1 on failure.
 */
static int get_exe_dir(char *exe_dir, size_t cap)
{
#ifdef _WIN32
    char buf[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, buf, (DWORD)sizeof(buf));
    if (len == 0 || len >= (DWORD)sizeof(buf))
        return -1;
    /* Accept both slash styles */
    char *sep = strrchr(buf, '\\');
    char *fwd = strrchr(buf, '/');
    char *slash = (sep > fwd) ? sep : fwd;
    if (!slash)
        return -1;
    *slash = '\0';
    if (strlen(buf) >= cap)
        return -1;
    strncpy(exe_dir, buf, cap - 1);
    exe_dir[cap - 1] = '\0';
    return 0;
#elif defined(__linux__)
    char buf[4096];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len < 0)
        return -1;
    buf[len] = '\0';
    char *slash = strrchr(buf, '/');
    if (!slash)
        return -1;
    *slash = '\0';
    if ((size_t)(slash - buf) >= cap)
        return -1;
    strncpy(exe_dir, buf, cap - 1);
    exe_dir[cap - 1] = '\0';
    return 0;
#elif defined(__APPLE__)
    char buf[4096];
    uint32_t size = (uint32_t)sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) != 0)
        return -1;
    char *slash = strrchr(buf, '/');
    if (!slash)
        return -1;
    *slash = '\0';
    if (strlen(buf) >= cap)
        return -1;
    strncpy(exe_dir, buf, cap - 1);
    exe_dir[cap - 1] = '\0';
    return 0;
#else
    (void)exe_dir;
    (void)cap;
    return -1;
#endif
}

/*
 * Tries to open 'filename' in the executable's directory, then the current
 * working directory.  Returns a FILE* opened for reading, or NULL.
 */
static FILE *open_adjacent(const char *filename)
{
    char path[4096];
    char exe_dir[4096];

    if (get_exe_dir(exe_dir, sizeof(exe_dir)) == 0) {
        snprintf(path, sizeof(path), "%s/%s", exe_dir, filename);
        FILE *f = fopen(path, "rb");
        if (f)
            return f;
    }

    /* Fallback: current working directory */
    return fopen(filename, "rb");
}

/*
 * Reads 'filename' and verifies that its total size equals 'expected_size'.
 * If the file is exactly that size, copies BF_KEY_TABLE_LENGTH bytes
 * starting at 'key_offset' into out_table.
 * Returns true on success.
 */
static bool try_load_key_from_file(const char *filename,
                                   long expected_size,
                                   long key_offset,
                                   uint8_t *out_table)
{
    FILE *f = open_adjacent(filename);
    if (!f)
        return false;

    bool ok = false;
    if (fseek(f, 0, SEEK_END) == 0) {
        long sz = ftell(f);
        if (sz == expected_size) {
            if (fseek(f, key_offset, SEEK_SET) == 0)
                ok = (fread(out_table, 1, BF_KEY_TABLE_LENGTH, f)
                      == BF_KEY_TABLE_LENGTH);
        }
    }
    fclose(f);
    return ok;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

bool blowfish_locator_get_ntr(uint8_t *out_table)
{
    /* 1. Try ntrBlowfish.bin directly */
    if (try_load_key_from_file(NTR_BLOWFISH_NAME,
                               (long)BF_KEY_TABLE_LENGTH, 0, out_table))
        return true;

    /* 2. Try extracting from a DS ARM7 BIOS dump */
    return try_load_key_from_file(BIOS_NDS7_NAME,
                                  BIOS_NDS7_LENGTH,
                                  BIOS_NDS7_BLOWFISH_OFFSET,
                                  out_table);
}

bool blowfish_locator_get_twl(uint8_t *out_table)
{
    /* 1. Try twlBlowfish.bin directly */
    if (try_load_key_from_file(TWL_BLOWFISH_NAME,
                               (long)BF_KEY_TABLE_LENGTH, 0, out_table))
        return true;

    /* 2. Try extracting from a DSi ARM7 BIOS dump */
    return try_load_key_from_file(BIOS_DSI7_NAME,
                                  BIOS_DSI7_LENGTH,
                                  BIOS_DSI7_BLOWFISH_OFFSET,
                                  out_table);
}

bool blowfish_locator_get_twl_dev(uint8_t *out_table)
{
    return try_load_key_from_file(TWL_DEV_BLOWFISH_NAME,
                                  (long)BF_KEY_TABLE_LENGTH, 0, out_table);
}
