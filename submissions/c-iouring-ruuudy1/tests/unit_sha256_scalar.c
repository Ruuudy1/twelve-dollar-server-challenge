// The SHA-256 tests built as a build without SHA-NI, so the portable-only configuration is compiled and run.
#undef __SHA__
#define FM_NO_SHA_NI 1
#include "unit_sha256.c"
