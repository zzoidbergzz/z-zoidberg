# MEMORY.md — z-zoidberg curated long-term memory

Per `AGENTS.md`, this file is the distilled long-term memory for the **main
session only**. Daily raw logs live under `memory/YYYY-MM-DD.md`. Curate
periodically: lift durable facts up here, drop outdated entries.

> **Security:** never paste secrets, API keys, tokens, or admin keys here.
> A pre-commit hook in `.githooks/pre-commit` greps for obvious patterns.
> Enable it once per clone with: `git config core.hooksPath .githooks`.

## Project Facts

- **z-zoidberg** is the agent persona + workspace at `/home/z/z-zoidberg`.
- **security-knowledge** (nested) is the FastAPI + Postgres + pgvector +
  Redis + ARQ + Alembic service that stores the security knowledge corpus.
- Custom HTTP RPC at `/api/v1/mcp/{tools,call}` — **not** real Model
  Context Protocol; real MCP SDK wrap is roadmap item B6.
- Provider registry self-populates via `@register` decorator on import
  (`app/enrichment/registry.py`); list providers in
  `app/enrichment/providers/__init__.py` to make them visible at startup.
- Truth-source endpoint (planned): `GET /api/v1/capabilities` (item A2).
  Until it lands, treat `TODO.md` Sections A–F + `AGENT_QUICKSTART.md` as
  the live oracle. Legacy ✅ marks in TODO are **not** trustworthy.
- Protected research environment: payloads, exploit code, weaponised PoCs,
  and offensive tooling **may** be stored verbatim in the corpus. Only
  restrictions: external-source licensing on republish, tenant RLS on
  writes. No defensive-only filter.

## People

- **Matthew** ("z" / "Zoidberg") — repo owner. Prefers concise, decisive
  responses; ask before destructive actions; never rewrite git history;
  never `gh pr merge` without his approval.

## Open Threads

- Improvement plan in motion (`chore/improvement-plan` branch merged
  TODO.md rewrite). Tracked via SQL `todos` table in the active session.
- Critical path: A1 → A2 → B2 → B5 → B1 → C3 → C1 → C2 → K1 → K2 → R1.

## Resolved

- 2026-05 — TODO.md rewritten as honest improvement plan; legacy 22-item
  roadmap kept below the fold as untrusted reference.
- 2026-05 — `feat/b2-provider-registry` opened: providers/__init__.py now
  imports the six shipped providers so `@register` actually fires.

---

*Last curation: see `memory/` for the date-stamped daily logs.*
