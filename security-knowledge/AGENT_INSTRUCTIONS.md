# Security Knowledge — Agent pointer

The canonical agent onboarding doc lives at the repo root:

**[/home/z/z-zoidberg/AGENT_QUICKSTART.md](../AGENT_QUICKSTART.md)**

It covers service-up, auth, capability discovery, recipes, dev loop, the
honest known-stubs list, and the project file map.

## Local dev loop (cheat-sheet)

```bash
make install       # editable install with dev extras
make migrate       # alembic upgrade head
make dev           # uvicorn --reload on :8000
make worker        # arq background worker
make test          # pytest -q
make lint          # ruff check
make fmt           # ruff format
make seed          # baseline seed data
make seed-knowledge  # full research-pack load
```

## Two project conventions worth remembering

1. **Enrichment providers self-register on import.** New providers must be
   listed in `app/enrichment/providers/__init__.py` so the `@register`
   decorator in `app/enrichment/registry.py` actually runs at startup.
2. **Adding a new entity kind:** update `EntityKind` in
   `app/models/entities.py`, `ENTITY_KIND_TO_STIX_TYPE` in
   `app/stix/mapping.py`, and the trigger map in
   `app/enrichment/triggers.py`.

Everything else — auth, MCP surface, recipes, decisions log, known stubs —
is in `AGENT_QUICKSTART.md`. Don't duplicate it here.
