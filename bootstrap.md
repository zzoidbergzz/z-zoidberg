# Bootstrap: MCP-Aware Research Corpus Ingestion

<!-- Prompt file index: docs/prompts.md
     This file: corpus onboarding contract (Mode A/B) for an LLM host.
     See also: prompt.md (coding-agent system prompt), deep-research-prompt.md (corpus generation — being rewritten on feat/r1-deep-research-prompt-v2). -->

Use this file to bootstrap another LLM host into this repository and the
`security-knowledge/` service. The host should be able to use the service's
runtime MCP dispatch, understand the current ingestion gaps, and feed either a
prepared research corpus or an extended prompt into the knowledge model without
losing provenance.

## Read Order

1. `AGENTS.md`, `SOUL.md`, `USER.md`, `IDENTITY.md`
2. `README.md`
3. `security-knowledge/AGENT_INSTRUCTIONS.md`
4. `security-knowledge/docs/mitre_attack.md`
5. `deep-research-prompt.md`
6. `security-knowledge/app/routers/mcp.py`
7. `security-knowledge/app/routers/ingest.py`
8. `security-knowledge/app/services/ingestion.py`
9. `security-knowledge/app/worker.py`
10. `security-knowledge/app/models/`
11. `security-knowledge/source-policy.yaml`

Trust code over roadmap prose. `TODO.md` describes the intended final product,
but it currently overstates what is complete.

## Service Startup

```bash
cd security-knowledge
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
cp .env.example .env
docker compose up -d
alembic upgrade head
python -m seed.seed_data
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Run the worker in another shell:

```bash
cd security-knowledge
. .venv/bin/activate
python -m arq app.worker.WorkerSettings
```

`python -m seed.seed_data` prints the admin API key once. Use that key as:

```text
X-API-Key: <seeded-key>
```

Prefer API-key auth for agent hosts. Bearer-token user flows exist, but the
agent ingestion path is simplest with a scoped API key.

## MCP Runtime Contract

The static manifest at `security-knowledge/mcp-tool-manifest.json` is stale and
only declares `enrich_entity`. Always introspect the live service:

```bash
curl -H "X-API-Key: $SK_API_KEY" \
  http://localhost:8000/api/v1/mcp/tools
```

Call tools through:

```http
POST /api/v1/mcp/call
Content-Type: application/json
X-API-Key: <key>

{
  "tool": "get_object_by_attack_id",
  "args": {
    "attack_id": "T1059",
    "domain": "enterprise"
  }
}
```

Runtime tools currently include:

- `enrich_entity`
- 30+ MITRE ATT&CK tools, including `get_object_by_attack_id`,
  `get_objects_by_name`, `get_techniques_used_by_group`,
  `get_groups_using_technique`, `get_datacomponents_detecting_technique`,
  `get_procedure_examples_by_technique`, `get_objects_created_after`, and
  `get_objects_modified_after`.

Important caveats:

- `enrich_entity` currently returns empty data and should be treated as a
  placeholder until wired to `EnrichmentService`.
- The provider registry is empty unless provider modules are imported. Fix
  `app/enrichment/providers/__init__.py` before relying on provider discovery.
- MITRE tools are the strongest MCP path today.

## Corpus Input Modes

There are two supported input modes for an external LLM host.

### Mode A: Prepared Research Corpus

Use this when the host already has a package matching `deep-research-prompt.md`.
Expected artifacts:

- `MANIFEST.md`
- `research-report.md`
- `sources.jsonl`
- `documents.jsonl`
- `sections.jsonl`
- `entities.jsonl`
- `facts.jsonl`
- `relationships.jsonl`
- `learning_units.jsonl`
- `context_packs.md`
- `sysinternals-pack.md`
- `pdf-ingestion-playbook.md`
- `import-plan.md`
- `quality-report.md`

Each JSONL file must contain one compact JSON object per line. Do not split a
JSON object across continuation parts. Every claim-like fact must cite evidence
or a source reference.

### Mode B: Extended Prompt Only

Use this when the host has an extended prompt or research brief but no corpus
artifacts yet.

Do not ingest prose directly as trusted knowledge. First convert the prompt into
the Mode A package:

1. Create or request `MANIFEST.md`.
2. Extract source candidates into `sources.jsonl`.
3. Produce normalized `documents.jsonl` and `sections.jsonl`.
4. Create canonical `entities.jsonl`.
5. Create atomic `facts.jsonl` with evidence references.
6. Create typed `relationships.jsonl`.
7. Write `import-plan.md` and `quality-report.md`.

Only then load records into the service.

## Data Model Mapping

Map corpus artifacts to current models as follows:

| Corpus artifact | Model/table | Notes |
| --- | --- | --- |
| `sources.jsonl` | `SourceRecord` / `sources` | Use canonical URL, title, source type, policy status, and `external_refs`. |
| fetched or uploaded content | `RawObject` / `raw_objects` | Store exact content, content type, SHA-256 hash, source id, tenant id. |
| `documents.jsonl` | `ParsedDocument` / `parsed_documents` | Preserve source id, title, URL, content type, word count, metadata. |
| `sections.jsonl` | `DocumentSection` / `document_sections` | Preserve document id, section index, heading path, content. Current model lacks page/offset fields; keep them in metadata if importer extends the schema. |
| `entities.jsonl` | `Entity`, `EntityAlias` | Upsert by external refs, then by kind plus canonical name. |
| `facts.jsonl` | `Claim` and `Evidence` | Create an atomic claim plus evidence rows with quote-sized snippets and source URLs. |
| `relationships.jsonl` | `Relationship` | Upsert by tenant, source entity, target entity, and relationship type. |
| embeddings | `ChunkEmbedding` | Generate after sections and evidence are stable. Current fallback can return zero vectors if no embedding API is configured. |
| `learning_units.jsonl` | Not modeled directly | Store as `Entity(kind="other")`, `Claim`, or add a proper learning-unit model before import. |
| `context_packs.md` | Not modeled directly | Keep as a generated artifact until a context-pack API exists. |

## Recommended Import Order

1. Validate JSONL syntax and required IDs.
2. Add or verify `source-policy.yaml` allow rules for every external domain
   before fetching content.
3. Import sources.
4. Fetch or attach raw objects and compute content hashes.
5. Import documents.
6. Import sections.
7. Import entities and aliases.
8. Import facts as claims.
9. Import evidence and link it to claims and entities.
10. Import relationships.
11. Generate embeddings.
12. Run search/MITRE/MCP spot checks.
13. Write a quality report with rejected records and unresolved source gaps.

## Current API Fallbacks

The service does not yet expose a bulk corpus import API. Available REST
fallbacks:

Create an entity:

```bash
curl -H "X-API-Key: $SK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"CVE-2024-1234","kind":"cve","description":"Example CVE"}' \
  http://localhost:8000/api/v1/entities/
```

Create a claim:

```bash
curl -H "X-API-Key: $SK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"statement":"CVE-2024-1234 affects Example Product","claim_type":"vulnerability","confidence":0.8}' \
  http://localhost:8000/api/v1/claims/
```

Create evidence:

```bash
curl -H "X-API-Key: $SK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"title":"Vendor advisory excerpt","content":"Short supporting quote.","source_url":"https://example.com/advisory"}' \
  http://localhost:8000/api/v1/evidence/
```

Queue an ingestion job:

```bash
curl -H "X-API-Key: $SK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"source_url":"https://example.com/advisory","source_type":"web"}' \
  http://localhost:8000/api/v1/ingest/
```

The queued ingestion job currently records and enqueues work, but the worker
does not yet perform the full ingest pipeline. For serious corpus loading, add
an importer or implement the worker pipeline first.

## Importer Requirements

If building the missing importer, keep it narrow and explicit:

- Accept a directory containing the Mode A artifacts.
- Require `tenant_id` or resolve it from the API key.
- Validate every JSONL object before writing any batch.
- Use transactions and write an import summary.
- Upsert idempotently:
  - Source by `source_id`, canonical URL, or URL.
  - Raw object by SHA-256 content hash.
  - Document by source id plus checksum or canonical document id.
  - Entity by external refs, then kind plus canonical name.
  - Claim by normalized statement plus source/evidence identity.
  - Relationship by source entity, target entity, relationship type, and source.
- Preserve original corpus IDs in `external_refs` or `properties`.
- Reject facts without evidence unless they are explicitly marked as
  unsupported background notes.
- Never overwrite reviewed claims destructively; create versions or changes.
- Emit audit events for import batches.

Recommended endpoint shape:

```http
POST /api/v1/import/corpus
Content-Type: multipart/form-data
X-API-Key: <key>

package=@cybersecurity-knowledge-seed-corpus.tar.zst
mode=validate_only|import
```

Recommended CLI shape:

```bash
python -m app.cli.import_corpus \
  --tenant-id "$TENANT_ID" \
  --package ./cybersecurity-knowledge-seed-corpus \
  --validate \
  --import
```

## Source And Safety Rules

- Keep the work defensive, educational, and authorized-testing oriented.
- Do not import turnkey exploit chains, malware code, credential theft
  automation, live-target recon instructions, secrets, leaked data, or long
  copyrighted excerpts.
- Store exact source metadata and hashes before derived claims.
- Keep evidence snippets short and quote-sized.
- Every material fact needs source and evidence references.
- Mark stale, uncertain, or single-source facts in claim properties.
- Enforce tenant IDs on every write.
- Respect `source-policy.yaml`; add explicit allow rules for Microsoft Learn,
  MITRE, NIST, CISA, FIRST, OWASP, OASIS, SigmaHQ, YARA, Suricata, Snort,
  Zeek, OpenCTI, MISP, and other corpus domains before network fetches.
- Do not log API keys, bearer tokens, provider secrets, raw credentials, or
  private corpus material.

## MCP-Aware Quality Checks

After import, run checks through both REST and MCP:

1. `GET /health`
2. `GET /api/v1/search/?q=sysmon`
3. `GET /api/v1/entities/?kind=attack_pattern`
4. `POST /api/v1/mcp/call` with `get_object_by_attack_id` for `T1059`.
5. `POST /api/v1/mcp/call` with `get_datacomponents_detecting_technique`.
6. `GET /api/v1/export/stix?limit=20`
7. Verify representative claims have evidence rows and source URLs.
8. Verify re-running the same import creates no duplicates.

## Known Work Before Full Corpus Import

These are the highest priority fixes for a production-grade bootstrap host:

1. Implement `process_ingest_job` end to end.
2. Add a corpus import endpoint or CLI.
3. Import enrichment providers at startup and update `mcp-tool-manifest.json`.
4. Wire `enrich_entity` MCP tool to `EnrichmentService`.
5. Add missing IPinfo, GreyNoise, and CrowdStrike providers or remove those
   claims from docs until implemented.
6. Replace `ILIKE` search with FTS/trigram ranking.
7. Add page number, offsets, and source artifact IDs to section/evidence schema
   or preserve them in structured metadata.
8. Add tests that import a tiny corpus package twice and verify idempotency.
