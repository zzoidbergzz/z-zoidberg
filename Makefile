# z-zoidberg root Makefile
#
# Most targets delegate into security-knowledge/Makefile.  This file exists
# so an agent or human dropping into the repo root can discover the dev
# loop with `make help` instead of having to cd first.

SK := security-knowledge

.PHONY: help agent-context up down test lint fmt type migrate manifest \
        seed seed-knowledge worker dev capabilities

help:  ## Show available targets
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_.-]+:.*?## / {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

agent-context:  ## Print the files a fresh agent should read first
	@echo "Read in this order:"
	@echo "  1. AGENT_QUICKSTART.md   — onboarding (item A1)"
	@echo "  2. AGENTS.md             — operating rules"
	@echo "  3. TODO.md               — Sections A–F (honest improvement plan)"
	@echo "  4. README.md             — project overview"
	@echo "  5. bootstrap.md          — corpus Mode A contract"
	@echo "  6. deep-research-prompt.md — extrapolation prompt v2 (item R1)"
	@echo "  7. MEMORY.md             — curated long-term memory"

up:  ## Bring up the security-knowledge stack (docker compose)
	$(MAKE) -C $(SK) docker-up

down:  ## Stop the security-knowledge stack
	$(MAKE) -C $(SK) docker-down

dev:  ## Run the FastAPI dev server with reload
	$(MAKE) -C $(SK) dev

worker:  ## Run the ARQ background worker
	$(MAKE) -C $(SK) worker

migrate:  ## Apply alembic migrations
	$(MAKE) -C $(SK) migrate

test:  ## Run pytest in security-knowledge
	$(MAKE) -C $(SK) test

lint:  ## ruff check
	$(MAKE) -C $(SK) lint

fmt:  ## ruff format
	$(MAKE) -C $(SK) fmt

type:  ## mypy (if configured in security-knowledge)
	cd $(SK) && (mypy app || echo "mypy not configured yet — see TODO P0.4")

seed:  ## Seed baseline data
	$(MAKE) -C $(SK) seed

seed-knowledge:  ## Seed full research-pack knowledge
	$(MAKE) -C $(SK) seed-knowledge

manifest:  ## Regenerate mcp-tool-manifest.json from the live registry (item A3)
	cd $(SK) && (python -m app.cli.dump_mcp_manifest > mcp-tool-manifest.json \
	    || echo "manifest dumper not implemented yet — see TODO A3")

capabilities:  ## Curl /api/v1/capabilities (planned A2)
	@curl -fsS http://localhost:8000/api/v1/capabilities | jq . \
	    || echo "capabilities endpoint not implemented yet — see TODO A2"
