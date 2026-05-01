CC      ?= gcc
# Disable -Wformat-security so the bug compiles; in production this
# warning would fire and refuse the build under -Werror.
CFLAGS  ?= -O0 -g -fno-stack-protector -fno-pie -no-pie -Wno-format-security -U_FORTIFY_SOURCE

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
