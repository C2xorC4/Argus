CC      ?= x86_64-w64-mingw32-gcc
CFLAGS  ?= -O0 -g
LDFLAGS ?= -Wl,--tsaware -Wl,--export-all-symbols

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
