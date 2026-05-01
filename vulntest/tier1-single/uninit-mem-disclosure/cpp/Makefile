CXX     ?= g++
CXXFLAGS?= -O0 -g -fno-stack-protector -fno-pie -no-pie -std=c++17 -Wno-uninitialized

SRC     := source/vuln.cpp
TARGET  := build/vuln

ifeq ($(OS),Windows_NT)
TARGET  := build/vuln.exe
endif

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC) | build
	$(CXX) $(CXXFLAGS) -o $@ $<

build:
	@mkdir -p build

clean:
	rm -rf build
