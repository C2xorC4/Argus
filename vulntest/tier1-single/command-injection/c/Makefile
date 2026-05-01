CC      ?= gcc
CFLAGS  ?= -O0 -g -fno-stack-protector -fno-pie -no-pie

SRC     := source/vuln.c
TARGET  := build/vuln

ifeq ($(OS),Windows_NT)
TARGET  := build/vuln.exe
endif

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC) | build
	$(CC) $(CFLAGS) -o $@ $<

build:
	@mkdir -p build

clean:
	rm -rf build
