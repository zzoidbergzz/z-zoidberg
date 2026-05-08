# Pre-commit Hook — `.githooks/pre-commit`

## Enable (once per clone)

```bash
git config core.hooksPath .githooks
```

## Checks

| # | What | Scope |
|---|------|-------|
| 1 | Secret-pattern grep | `MEMORY.md`, `memory/*.md` |
| 2 | Block edits to existing Alembic migrations | `alembic/versions/*.py` |
| 3 | `ruff format --check` | Staged `security-knowledge/**/*.py` |
| 4 | `ruff check` (lint) | Same staged Python files |

Checks 3–4 skip (warn-only) if `ruff` is not on `PATH` (`pip install ruff`).
Fix: `make fmt` for format errors; fix lint errors and re-stage; never edit an
existing Alembic revision — add a new one.

## Bypass (emergency only)

```bash
git commit --no-verify  # document why in the commit body
```

## Supersedes feat/a5-memory-skeleton

That branch adds checks 1–2 only. This hook is a strict superset; once both
PRs land, A5 can be closed in favour of this one.
