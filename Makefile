.PHONY: build release install clean fmt lint check test

build:
	cargo build

release:
	cargo build --release

install:
	cargo install --path .

clean:
	cargo clean

fmt:
	cargo fmt

lint:
	cargo clippy

check: fmt lint build
	@echo "All checks passed"

test:
	cargo test
