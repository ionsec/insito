# INSITO - Rhysida ESXi decryption tool (single-file C, vendored LibTomCrypt/LibTomMath).
# See README.md (build) and tests/README.md (test suite).

CC ?= cc
WARN ?= -Wall -Wextra
CFLAGS_STATIC ?= -O2 -s
DEFS ?= -DUSE_LTM -DLTM_DESC -DESXI_KEY
LTC_HEADERDIR ?= vendor/libtomcrypt/src/headers
# link order matters: the math-descriptor object must come before libtomcrypt.a
STATIC_LIBS ?= vendor/ltm_desc3.o vendor/libtomcrypt.a vendor/libtommath.a

.DEFAULT_GOAL := all
.PHONY: help all build test static vendor vendor-clean clean

help: ## list targets
	@echo "make all|build|static | make test | make vendor | make vendor-clean | make clean"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: static ## build insito (static release binary)
build: static ## alias for all

static: vendor ## canonical static build (see README.md)
	@test -f pubkey_elf.h || { echo "ERROR: pubkey_elf.h missing - the embedded TEST-ONLY public key header (see tests/README.md)"; exit 1; }
	$(CC) $(CFLAGS_STATIC) -static $(WARN) $(DEFS) -I$(LTC_HEADERDIR) -o insito insito.c $(STATIC_LIBS)

test: static ## build + run the test suite (tests/run.sh)
	bash tests/run.sh

vendor: ## vendored static libs at vendor/ root (compiled from source when absent)
	@[ -f vendor/libtommath.a ] || { \
	  if [ -f vendor/libtommath/libtommath.a ]; then cp -f vendor/libtommath/libtommath.a vendor/; \
	  else $(MAKE) -C vendor/libtommath && cp -f vendor/libtommath/libtommath.a vendor/; fi; }
	@[ -f vendor/libtomcrypt.a ] || { \
	  if [ -f vendor/libtomcrypt/libtomcrypt.a ]; then cp -f vendor/libtomcrypt/libtomcrypt.a vendor/; \
	  else $(MAKE) -C vendor/libtomcrypt CFLAGS="-O2 -DUSE_LTM -I../libtommath" && cp -f vendor/libtomcrypt/libtomcrypt.a vendor/; fi; }
	@[ -f vendor/ltm_desc3.o ] || $(CC) -O2 -Wall -Wextra -DUSE_LTM -DLTM_DESC -I$(LTC_HEADERDIR) -Ivendor/libtommath -c vendor/libtomcrypt/src/math/ltm_desc.c -o vendor/ltm_desc3.o

vendor-clean: ## remove vendored build products (forces a from-source rebuild)
	rm -f vendor/libtomcrypt.a vendor/libtommath.a vendor/ltm_desc3.o
	rm -f vendor/libtomcrypt/libtomcrypt.a vendor/libtommath/libtommath.a
	find vendor -type f -name '*.o' -delete

clean: ## remove local build outputs (keeps vendored libs)
	rm -f insito insito-asan SHA256SUMS
	rm -rf testsynthetic
