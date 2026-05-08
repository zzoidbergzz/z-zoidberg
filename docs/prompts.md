# Prompt File Index

This repo contains three prompt files with distinct purposes. None duplicates
another — do not merge or delete them without reading the lifecycle notes below.

## Files

### `prompt.md`
| Field | Value |
|---|---|
| Purpose | Persona / system prompt handed to a **downstream LLM** implementing the Security Knowledge Service roadmap. Describes composite implementation order, hard constraints, and when to stop and ask. |
| Primary consumer | External LLM (e.g. GPT-4, Claude) acting as a coding agent |
| Lifecycle owner | Human operator — update when roadmap order or hard-constraints change |
| Relationship | References `TODO.md` as the single source of truth for spec. |

### `bootstrap.md`
| Field | Value |
|---|---|
| Purpose | **Mode A corpus contract** — how to bootstrap a fresh LLM host into this repo, start the service, call MCP tools, and load or convert a research corpus. |
| Primary consumer | Agent / LLM host being onboarded to the `security-knowledge/` service |
| Lifecycle owner | Human operator — update when service startup, MCP endpoints, or import path changes |
| Relationship | Calls out `deep-research-prompt.md` as the expected corpus source (Mode A). Overlaps with `deep-research-prompt.md` only on corpus artifact names — that overlap is intentional; do not deduplicate without a TODO review. |

### `deep-research-prompt.md`
| Field | Value |
|---|---|
| Purpose | Prompt for **Deep Research** (or equivalent agent) to produce an import-ready cybersecurity learning corpus package. Defines all expected JSONL artifact formats. |
| Primary consumer | Deep Research agent / standalone research LLM |
| Lifecycle owner | Human operator — **currently being rewritten on branch `feat/r1-deep-research-prompt-v2`**; do not edit on other branches |
| Relationship | Output feeds into `bootstrap.md` Mode A ingestion path. |

## Overlap Notes

`bootstrap.md` §"Mode A" lists the same artifact names defined in
`deep-research-prompt.md`. This is a deliberate contract reference, not
redundancy — `bootstrap.md` names what to expect; `deep-research-prompt.md`
defines how to produce it.

<!-- TODO: once feat/r1-deep-research-prompt-v2 lands, review bootstrap.md
     Mode A artifact list for drift and update this index. -->
