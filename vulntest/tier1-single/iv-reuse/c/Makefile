# Windows-only cell. Default uses MinGW-w64; build_all.sh shells via
# MSVC (vcvars64) for cross-toolchain consistency with the other cells.

CC      ?= x86_64-w64-mingw32-gcc
CFLAGS  ?= -O0 -g -municode -DUNICODE -D_UNICODE
LDFLAGS ?= -lbcrypt

SRC     := source/vuln.c
TARGET  := build/vuln.exe

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC) | build
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

build:
	@mkdir -p build

clean:
	rm -rf build
