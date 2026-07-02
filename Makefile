SHELL := /bin/bash
SCRIPTS_DIR := scripts
SCHEMAS_DIR := schemas

.PHONY: help lint typecheck validate-schemas validate-models init run-step redact validate commit-run test smoke ci ipk clean nostr-key nostr-publish-issue nostr-update-status nostr-query-board nostr-query-issue nostr-relays nostr-verify

help: ## Show this help
	@echo "Usage: make [target] [ARGS='...']"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

lint: ## Run ruff and shell script syntax checks
	@echo "Running ruff..."
	@ruff check scripts tests
	@echo "Linting shell scripts..."
	@FAIL=0; \
	for f in $(SCRIPTS_DIR)/*.sh $(SCRIPTS_DIR)/lib/*.sh; do \
		if [ -f "$$f" ]; then \
			if ! bash -n "$$f"; then \
				echo "FAIL: $$f"; \
				FAIL=1; \
			else \
				echo "  OK: $$f"; \
			fi; \
		fi; \
	done; \
	if [ "$$FAIL" -ne 0 ]; then exit 1; fi

typecheck: ## Run Python static type checking
	@pyright scripts tests

validate-schemas: ## Compile all JSON schemas with ajv-cli@5
	@echo "Validating schemas..."
	@FAIL=0; \
	for s in $(SCHEMAS_DIR)/*.schema.json; do \
		if ! npx -y ajv-cli@5 compile -s "$$s"; then \
			echo "FAIL: $$s"; \
			FAIL=1; \
		else \
			echo "  OK: $$s"; \
		fi; \
	done; \
	if [ "$$FAIL" -ne 0 ]; then exit 1; fi

validate-models: ## Validate all models/*.json against schemas/model.schema.json
	@python3 scripts/validate_models.py

init: ## Initialize a new run (wraps scripts/init-run.sh)
	@echo "Initializing run..."
	@$(SCRIPTS_DIR)/init-run.sh $(ARGS)
## Usage: make init ARGS="--target 192.168.1.1 --operator alice"

run-step: ## Execute a step (wraps scripts/run-step.sh)
	@echo "Running step..."
	@$(SCRIPTS_DIR)/run-step.sh $(ARGS)
## Usage: make run-step ARGS="--run-id <id> --step <step>"

redact: ## Redact run output (wraps scripts/redact-output.sh)
	@echo "Redacting output..."
	@$(SCRIPTS_DIR)/redact-output.sh $(ARGS)

validate: ## Validate findings JSON (wraps scripts/validate-findings.sh)
	@echo "Validating findings..."
	@$(SCRIPTS_DIR)/validate-findings.sh $(ARGS)

commit-run: ## Commit redacted artifacts (wraps scripts/commit-run.sh)
	@echo "Committing run artifacts..."
	@$(SCRIPTS_DIR)/commit-run.sh $(ARGS)

test: ## Run Python unit tests plus existing safe shell smoke test
	@pytest tests
	@$(MAKE) smoke
	@if command -v bats >/dev/null 2>&1; then \
		bats tests/*.bats; \
	else \
		echo "bats-core is not installed; skipping bats tests (smoke still ran)"; \
	fi
smoke: ## End-to-end smoke test
	@if [ ! -f tests/smoke.sh ]; then \
		echo "smoke test not yet created"; \
		exit 0; \
	fi
	@bash tests/smoke.sh

ci: ## Run all hardware-safe CI checks
	@$(MAKE) lint
	@$(MAKE) typecheck
	@$(MAKE) validate-schemas
	@$(MAKE) validate-models
	@$(MAKE) test

ipk: ## Build conwrt ipk for OpenWrt
	@$(SCRIPTS_DIR)/build_ipk.sh --output dist $(ARGS)

clean: ## Remove .tmp files from runs/
	@echo "Cleaning .tmp directories..."
	@find runs/ -type d -name '.tmp' -exec rm -rf {} + 2>/dev/null || true
	@echo "Done."

## ─── Nostr / NIP-34 targets (nak CLI) ───────────────────────────
## Requires: ~/.local/bin/nak and NOSTR_SECRET_KEY env var (hex)
NAK ?= ~/.local/bin/nak
RELAYS ?= wss://relay.damus.io wss://nos.lol
SEC ?= $(NOSTR_SECRET_KEY)
BOARD_ID ?= net4sats-mvp-board
PUBKEY ?= e18a1d171a59d874edd336472afeb3a614d3dc83397dd097e922a99dcee02133

nostr-key: ## Show the npub for the configured secret key
	@if [ -z "$(SEC)" ]; then echo "ERROR: Set NOSTR_SECRET_KEY env var"; exit 1; fi
	@$(NAK) key public --sec "$(SEC)"

nostr-publish-issue: ## Publish a NIP-34 issue. Usage: make nostr-publish-issue title="Bug" body="Description"
	@if [ -z "$(SEC)" ]; then echo "ERROR: Set NOSTR_SECRET_KEY env var"; exit 1; fi
	@if [ -z "$(title)" ]; then echo "ERROR: title=... required"; exit 1; fi
	@$(NAK) event --sec "$(SEC)" -k 30311 \
		-c "$(if $(body),$(body),No description provided)" \
		-d "$(BOARD_ID)" \
		-t "title=$(title)" \
		-t "status=open" \
		$(RELAYS)

nostr-update-status: ## Update issue status. Usage: make nostr-update-status id="event-id" status="closed"
	@if [ -z "$(SEC)" ]; then echo "ERROR: Set NOSTR_SECRET_KEY env var"; exit 1; fi
	@if [ -z "$(id)" ] || [ -z "$(status)" ]; then echo "ERROR: id=... and status=... required"; exit 1; fi
	@$(NAK) event --sec "$(SEC)" -k 30311 \
		-c "Status update: $(status)" \
		-e "$(id)" \
		-t "status=$(status)" \
		$(RELAYS)

nostr-query-board: ## Fetch all board events from relays
	@echo "Querying board $(BOARD_ID) for pubkey $(PUBKEY)..."
	@$(NAK) req -a $(PUBKEY) -k 30311 -l 50 $(RELAYS)

nostr-query-issue: ## Fetch a specific issue. Usage: make nostr-query-issue id="event-id"
	@if [ -z "$(id)" ]; then echo "ERROR: id=... required"; exit 1; fi
	@$(NAK) fetch $(id) $(RELAYS)

nostr-relays: ## Check relay connectivity
	@for r in $(RELAYS); do \
		echo -n "$$r: "; \
		$(NAK) relay "$$r" 2>&1 | head -1 || echo "FAILED"; \
	done

nostr-verify: ## Verify an event signature from stdin
	@$(NAK) verify

.PHONY: nostr-key nostr-publish-issue nostr-update-status nostr-query-board nostr-query-issue nostr-relays nostr-verify
