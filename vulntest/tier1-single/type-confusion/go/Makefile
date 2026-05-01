.PHONY: all clean

all: build/vuln

build/vuln: source/main.go | build
	cd source && go build -o ../build/vuln .

build:
	@mkdir -p build

clean:
	rm -rf build
