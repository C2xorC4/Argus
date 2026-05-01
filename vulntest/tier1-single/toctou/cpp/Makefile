CXX     ?= g++
CXXFLAGS?= -O0 -g -fno-stack-protector -fno-pie -no-pie -std=c++17

SRC     := source/vuln.cpp
TARGET  := build/vuln

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC) | build
	$(CXX) $(CXXFLAGS) -o $@ $<

build:
	@mkdir -p build

clean:
	rm -rf build
