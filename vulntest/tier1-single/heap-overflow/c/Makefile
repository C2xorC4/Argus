CC      ?= gcc
CFLAGS  ?= -O0 -g -fno-stack-protector -fno-pie -no-pie
LDFLAGS ?=

SRC     := source/vuln.c
TARGET  := build/vuln

ifeq ($(OS),Windows_NT)
TARGET  := build/vuln.exe
endif

.PHONY: all clean asan

all: $(TARGET)

$(TARGET): $(SRC) | build
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

asan: $(SRC) | build
	$(CC) $(CFLAGS) -fsanitize=address -o build/vuln-asan $< $(LDFLAGS)

build:
	@mkdir -p build

clean:
	rm -rf build
