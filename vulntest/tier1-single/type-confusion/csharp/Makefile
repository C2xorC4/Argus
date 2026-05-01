CSC ?= csc

SRC := source/Vuln.cs
TARGET := build/Vuln.exe

all: $(TARGET)

$(TARGET): $(SRC) | build
	$(CSC) /unsafe /out:$@ $<

build:
	@mkdir -p build

clean:
	rm -rf build

.PHONY: all clean
