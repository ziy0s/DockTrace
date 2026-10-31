# Production eBPF build system for Learn

# Tools
CLANG    ?= clang
BPFTOOL  ?= bpftool
CC       ?= gcc
STRIP    ?= strip

# Project
APP      := Learn
SRC_DIR  := src
BPF_SRC  := $(SRC_DIR)/$(APP).bpf.c
BPF_OBJ  := $(APP).bpf.o
SKEL     := $(SRC_DIR)/$(APP).skel.h
USER_SRC := $(SRC_DIR)/main.c
OUTPUT   := $(APP)

# BPF compilation flags
BPF_CFLAGS := -O2 -g -target bpf \
    -D__TARGET_ARCH_x86 \
    -I$(SRC_DIR) \
    -I/usr/local/include

# User-space compilation flags
USER_CFLAGS := -O2 -g -Wall \
    -I$(SRC_DIR) \
    -I/usr/local/include

# Linker flags
LIBBPF_STATIC := $(shell find /usr/local -name libbpf.a 2>/dev/null | head -n 1)
ifeq ($(LIBBPF_STATIC),)
    LDFLAGS := -L/usr/local/lib -L/usr/local/lib64 -lbpf -lelf -lz
else
    LDFLAGS := $(LIBBPF_STATIC) -lelf -lz
endif

# Default target
all: $(OUTPUT)

# Step 1: Generate vmlinux.h
$(SRC_DIR)/vmlinux.h:
	@echo "=== Generating vmlinux.h ==="
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Step 2: Compile BPF program
$(BPF_OBJ): $(BPF_SRC) $(SRC_DIR)/vmlinux.h $(SRC_DIR)/$(APP).h
	@echo "=== Compiling BPF program ==="
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Step 3: Generate skeleton
$(SKEL): $(BPF_OBJ)
	@echo "=== Generating skeleton ==="
	$(BPFTOOL) gen skeleton $< > $@

# Step 4: Compile user-space program
$(OUTPUT): $(USER_SRC) $(SKEL) $(SRC_DIR)/$(APP).h
	@echo "=== Compiling user-space loader ==="
	$(CC) $(USER_CFLAGS) $< -o $@ $(LDFLAGS)

# Run
run: $(OUTPUT)
	sudo ./$(OUTPUT)

# Clean
clean:
	rm -f $(BPF_OBJ) $(SKEL) $(OUTPUT)

# Install
install: $(OUTPUT)
	install -m 755 $(OUTPUT) /usr/local/bin/$(OUTPUT)

# Generate skeleton first time
skel: $(SKEL)

.PHONY: all run clean install
