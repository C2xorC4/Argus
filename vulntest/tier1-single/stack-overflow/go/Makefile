.PHONY: all clean

all: build/vuln

build/vuln: source/main.go | build
	cd source && CGO_ENABLED=1 go build -o ../build/vuln .

build:
	@mkdir -p build

clean:
	rm -rf build
