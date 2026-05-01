CSC ?= csc

SRC := source/Vuln.cs
TARGET := build/Vuln.exe

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC) | build
	$(CSC) /out:$@ $<

build:
	@mkdir -p build

clean:
	rm -rf build
