TARGET = x86_64-unknown-linux-musl
BUILD_MODE = --release
OUTPUT_DIR = target/$(TARGET)/release
BINARY_NAME = jacoco_parser

.PHONY: all build clean

all: build

build:
	rustup target add x86_64-unknown-linux-musl
	cargo build --target=$(TARGET) $(BUILD_MODE)

clean:
	cargo clean

print-bin:
	@echo $(OUTPUT_DIR)/$(BINARY_NAME)
