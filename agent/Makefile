.PHONY: test build clean help

# Delegate to root Makefile for most tasks
# This file exists for convenience when working in the agent/ directory

test:
	@$(MAKE) -C .. test-agent

build:
	@cargo build -p agent

clean:
	@$(MAKE) -C .. clean

help:
	@echo "Agent Makefile (delegates to root)"
	@echo ""
	@echo "  make test       - Run agent tests (delegates to root Makefile)"
	@echo "  make build      - Build agent package"
	@echo "  make clean      - Clean up (delegates to root Makefile)"
	@echo ""
	@echo "For full options, run 'make help' from repo root"
