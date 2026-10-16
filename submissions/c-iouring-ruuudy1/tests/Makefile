# Test scaffold, not built by build.sh. Run build.sh once first so deps/ exists.
#
#   make unit    plain build of every unit_*.c, then run it
#   make asan    same programs with address and undefined sanitizers (no PGO), run with abort on any finding
#   make fuzz    sanitized build of every fuzz_*.c, run for FUZZ_ITERS iterations (default 200000)
#
# A test program is one C file that defines FM_TEST, includes ../src/main.c and has its own main().
# SQLite is compiled once into build/tests/sqlite3.o and linked in, so test builds stay fast.
SHELL := bash
ROOT := ..
CC := gcc
CFLAGS_REL := $(shell bash $(ROOT)/build.sh --print-cflags)
SQLITE_DEFS := $(shell bash $(ROOT)/build.sh --print-sqlite-defs)
INCLUDES := -I$(ROOT)/src -isystem $(ROOT)/deps/sqlite -isystem $(ROOT)/deps/liburing/src/include
LIBURING := $(ROOT)/deps/liburing/src/liburing.a
OUT := $(ROOT)/build/tests
FUZZ_ITERS ?= 200000
UNIT_SRCS := $(sort $(wildcard unit_*.c))
FUZZ_SRCS := $(sort $(wildcard fuzz_*.c))
COMMON := -std=gnu17 -Wall -Wextra -Wno-unused-function -g -DFM_TEST -DFM_EXTERNAL_SQLITE $(SQLITE_DEFS) $(INCLUDES)
PLAIN := -O1 $(COMMON)
SAN := -O1 -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer $(COMMON)
SRC_DEPS := $(wildcard $(ROOT)/src/*.c $(ROOT)/src/*.h)

.SECONDARY:
.PHONY: unit asan fuzz clean
unit: $(UNIT_SRCS:%.c=$(OUT)/plain/%.run)
asan: $(UNIT_SRCS:%.c=$(OUT)/asan/%.run)
fuzz: $(FUZZ_SRCS:%.c=$(OUT)/fuzz/%.run)
clean:
	rm -rf $(OUT)

$(OUT)/sqlite3.o: $(ROOT)/deps/sqlite/sqlite3.c $(ROOT)/build.sh
	@mkdir -p $(OUT)
	$(CC) -O2 -w $(SQLITE_DEFS) -isystem $(ROOT)/deps/sqlite -c $< -o $@

$(OUT)/plain/%: %.c $(SRC_DEPS) $(OUT)/sqlite3.o
	@mkdir -p $(dir $@)
	$(CC) $(PLAIN) $< $(OUT)/sqlite3.o $(LIBURING) -o $@

$(OUT)/asan/%: %.c $(SRC_DEPS) $(OUT)/sqlite3.o
	@mkdir -p $(dir $@)
	$(CC) $(SAN) $< $(OUT)/sqlite3.o $(LIBURING) -o $@

$(OUT)/fuzz/%: %.c $(SRC_DEPS) $(OUT)/sqlite3.o
	@mkdir -p $(dir $@)
	$(CC) $(SAN) $< $(OUT)/sqlite3.o $(LIBURING) -o $@

$(OUT)/plain/%.run: $(OUT)/plain/%
	$<

$(OUT)/asan/%.run: $(OUT)/asan/%
	ASAN_OPTIONS=abort_on_error=1:detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1 $<

$(OUT)/fuzz/%.run: $(OUT)/fuzz/%
	ASAN_OPTIONS=abort_on_error=1 UBSAN_OPTIONS=print_stacktrace=1 $< $(FUZZ_ITERS)
