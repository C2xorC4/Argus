CC      ?= gcc
CFLAGS  ?= -O0 -g -fno-stack-protector -fno-pie -no-pie

SRC     := source/vuln.c
TARGET  := build/vuln

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC) | build
	$(CC) $(CFLAGS) -o $@ $<

build:
	@mkdir -p build

clean:
	rm -rf build
