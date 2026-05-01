CC      ?= x86_64-w64-mingw32-gcc
CFLAGS  ?= -O0 -g -municode -DUNICODE -D_UNICODE

SRC     := source/vuln.c
TARGET  := build/vuln.exe

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC) | build
	$(CC) $(CFLAGS) -o $@ $<

build:
	@mkdir -p build

clean:
	rm -rf build
