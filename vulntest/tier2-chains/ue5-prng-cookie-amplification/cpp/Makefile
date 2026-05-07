# Tier-2 UE5 chain skeleton. Default uses MinGW-w64 g++; build_all.sh
# shells via MSVC (vcvars64) for cross-toolchain consistency.

CXX     ?= x86_64-w64-mingw32-g++
CXXFLAGS ?= -O0 -g -std=c++17

SRC     := source/vuln.cpp
TARGET  := build/vuln.exe

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC) | build
	$(CXX) $(CXXFLAGS) -o $@ $<

build:
	@mkdir -p build

clean:
	rm -rf build
