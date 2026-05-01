.PHONY: all clean

all: build/vuln

build/vuln: source/src/main.rs source/Cargo.toml | build
	cd source && cargo build --target-dir ../build_target
	cp build_target/debug/vuln build/vuln 2>/dev/null || cp build_target/debug/vuln.exe build/vuln.exe

build:
	@mkdir -p build

clean:
	rm -rf build build_target source/Cargo.lock
