# Windows-only cell — requires MinGW-w64 or MSVC. Default uses
# x86_64-w64-mingw32-gcc; adjust CC for native MSVC builds.

CC      ?= x86_64-w64-mingw32-gcc
CFLAGS  ?= -O0 -g -municode -DUNICODE -D_UNICODE
LDFLAGS ?= -ladvapi32

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
