CC      ?= gcc
CFLAGS  ?= -O0 -g -fno-stack-protector -fno-pie -no-pie -Wno-uninitialized

SRC     := source/vuln.c
TARGET  := build/vuln

ifeq ($(OS),Windows_NT)
TARGET  := build/vuln.exe
endif

.PHONY: all clean msan

all: $(TARGET)

$(TARGET): $(SRC) | build
	$(CC) $(CFLAGS) -o $@ $<

msan: $(SRC) | build
	clang $(CFLAGS) -fsanitize=memory -fno-omit-frame-pointer -o build/vuln-msan $<

build:
	@mkdir -p build

clean:
	rm -rf build
