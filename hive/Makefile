.PHONY: test test-worker build clean help

# Delegate to root Makefile for most tasks
# This file exists for convenience when working in the hive/ directory

test:
	@$(MAKE) -C .. test-hive

test-worker:
	@$(MAKE) -C .. test-hive

build:
	@cargo build -p hive

clean:
	@$(MAKE) -C .. clean

help:
	@echo "Hive Makefile (delegates to root)"
	@echo ""
	@echo "  make test       - Run hive tests (delegates to root Makefile)"
	@echo "  make build      - Build hive package"
	@echo "  make clean      - Clean up (delegates to root Makefile)"
	@echo ""
	@echo "For full options, run 'make help' from repo root"
