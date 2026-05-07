# Downstream LLM Prompt — Security Knowledge Service Roadmap

## File order

1. **PLAN.md** first — items 1–11 (foundational features: auth, async queue, embeddings, FTS, NVD/EUVD adapters, etc.)
2. **PLAN-EXTENSIONS.md** second — items 12–21 (extensions). Read its **Cross-Cutting Implementation Rules** section before writing any code, and apply those rules to BOTH files.

## Composite implementation order

```
6 → 18 → 2 → 7 → 17 → 3 → 1 → 8 → 11 → 12 → 15 → 4 → 5 → 10 → 13 → 16 → 19 → 9 → 14 → 20 → 21
```

(Auth → Observability → Async queue → FTS → Webhooks → … so cross-cutting infra exists before features that need it.)

---

## Prompt to give the downstream LLM

```
You are implementing the Security Knowledge Service roadmap. Two specs:

  1. PLAN.md            — items 1-11 (foundational features)
  2. PLAN-EXTENSIONS.md — items 12-21 (extensions; read the
                          "Cross-Cutting Implementation Rules"
                          section before writing any code, and
                          apply those rules to BOTH files)

Work strictly in this order:
  6 → 18 → 2 → 7 → 17 → 3 → 1 → 8 → 11 → 12 → 15 → 4 → 5 → 10 →
  13 → 16 → 19 → 9 → 14 → 20 → 21

For each item:
  1. Read the item's section in full. Re-read its dependencies.
  2. Create a branch: feat/<item-number>-<short-name>
  3. Write Alembic migrations (upgrade + downgrade) for any schema
     change. Tenant-scope every new table (RLS per item #6).
  4. Implement exactly the files listed under "Files" for that item.
     Do not invent extra modules. Do not skip listed files.
  5. Add unit tests as specified. Tests must pass and coverage of
     touched modules must not drop.
  6. Run: ruff check, ruff format --check, mypy, pytest. All green.
  7. Update .env.example, source-policy.yaml, mcp-tool-manifest.json,
     and docs/<item>.md per the cross-cutting rules.
  8. Commit with message: "feat(#<n>): <item title>" and the
     Co-authored-by: Copilot trailer. Open a PR; merge only when
     CI is green.
  9. Move to the next item. Never start an item whose dependencies
     are unmerged.

Hard constraints:
  - Async-first (httpx.AsyncClient, asyncio.Semaphore for bounds).
  - Idempotent external integrations (re-run = no duplicates).
  - Provenance: every imported claim/entity stores external_refs.
  - Never log secrets; mask provider keys in traces.
  - Never edit an existing Alembic revision; always add a new one.
  - If a spec is ambiguous, prefer the option that (a) matches
    existing patterns in the codebase, (b) is reversible, (c) is
    cheaper to operate. Document the choice in the PR description.

Stop and ask the human if:
  - A dependency listed in the order above is missing or broken.
  - A migration would require destructive data loss.
  - An external API requires paid credentials not in .env.example.
  - Two items conflict on a schema or interface change.

Begin with item #6 (Authentication & Authorisation) from PLAN.md.
```
