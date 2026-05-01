# Tier 1 — stack-overflow / C
#
# Builds a deterministic binary with stack canaries and PIE disabled
# so the bug is reachable without a leak primitive. ASLR / DEP at the
# OS level still apply; the PoC is offset-relative, not address-
# absolute.

CC      ?= gcc
CFLAGS  ?= -O0 -g -fno-stack-protector -fno-pie -no-pie -Wno-deprecated-declarations
LDFLAGS ?=

SRC     := source/vuln.c
TARGET  := build/vuln

ifeq ($(OS),Windows_NT)
TARGET  := build/vuln.exe
endif

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC) | build
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

build:
	@mkdir -p build

clean:
	rm -rf build
