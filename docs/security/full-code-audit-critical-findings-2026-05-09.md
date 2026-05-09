# Full code audit — critical findings — 2026-05-09

Scope: static security audit of the `security-knowledge` FastAPI application, MCP transports/tools, worker dispatch paths, and high-risk local-file/network primitives. This is a follow-up to `critical-vulnerability-audit-2026-05-09.md`; the earlier five findings are treated as previously documented/fixed and are not repeated here except where a related surface remains exposed.

## Methodology

- Reviewed auth/RBAC boundaries in FastAPI routers, GraphQL, MCP HTTP, and MCP SSE.
- Grepped for high-risk primitives: external network calls, local file access, archive handling, subprocess use, raw SQL, unauthenticated routes, tenant filters, and user-controlled path/URL fields.
- Focused on critical-impact classes: tenant isolation breaks, arbitrary file read/write, SSRF/internal network reachability, privilege bypass, and RCE-adjacent primitives.

Commands used during review:

```bash
find .. -name AGENTS.md -print
rg --files security-knowledge/app security-knowledge/tests
rg -n "extractall|subprocess|os\.system|shell=True|eval\(|exec\(|pickle|yaml\.load|httpx\.|AsyncClient|open\(|Path\(|tar|zipfile|tenant_id|require_scope|Depends\(|UploadFile|webhook|graphql|CORSMiddleware" app -g '*.py'
for f in app/routers/*.py; do rg -n "@router\.|Depends\(get_auth|require_scope|auth\.require_scope|tenant_id|select\(|where\(" "$f"; done
rg -n "text\(f|f\".*SELECT|execute\(f|ORDER BY|order_by\(|limit|offset|tenant_id == auth\.tenant_id" app -g '*.py'
```

## 1. MCP SSE transport grants write scope to every valid API key and does not enforce tool scopes

**Severity:** Critical — write-scope authorization bypass via MCP SSE.
**Status:** Open.

**Impact:** Any valid API key that can authenticate to `/api/v1/mcp/sse` can invoke registered write tools such as `create_entity`, `create_claim`, `create_evidence`, `ingest_url`, `create_digest_subscription`, and `add_source` even if the key has only `read` scope. This bypasses the scope enforcement present in the JSON-RPC-like `/api/v1/mcp/call` route.

**Evidence:**

- `_auth_middleware` validates that an API key exists, but it stores only tenant/user/key identifiers in ASGI state; it does not preserve the key's stored scopes.
- `_build_auth` constructs the tool `AuthContext` with unconditional `[Scope.read, Scope.write]`.
- The SSE `handle_call_tool` path calls `tool.fn(args, db, auth)` directly and never checks `tool.scope` before dispatch.
- In contrast, `app/routers/mcp.py` checks `tool.scope == "write"` and requires `Scope.write` for the HTTP `/mcp/call` route.

**Exploit sketch:** Create or obtain a read-only API key, connect to `/api/v1/mcp/sse` with `X-API-Key`, then invoke any registered write tool. The server-created `AuthContext` contains write scope regardless of the database row.

**Recommended fix:** Carry the parsed API-key scopes from `_auth_middleware` into request state; build `AuthContext` with those scopes; enforce `tool.scope` in `handle_call_tool`; add tests proving a read-only key cannot call write tools over SSE.

## 2. MCP SSE tool calls currently fail at runtime because `_build_auth` passes an unsupported constructor argument

**Severity:** Critical bug for the MCP SSE feature — authenticated remote MCP tool execution is broken.
**Status:** Open.

**Impact:** `_build_auth` passes `api_key=...` to `AuthContext`, but `AuthContext.__init__` has no `api_key` parameter. Any SSE tool invocation that reaches `_build_auth` raises `TypeError`, causing the remote MCP transport to fail. This is both an availability bug and a masking issue: once fixed, finding #1 becomes directly exploitable unless scope enforcement is fixed at the same time.

**Evidence:**

- `AuthContext.__init__` accepts `tenant_id`, `scopes`, `user_id`, `user_email`, and `auth_type` only.
- `_build_auth` passes `api_key=api_key or os.environ.get("SK_API_KEY", "")`.

**Recommended fix:** Remove the unsupported argument or add an explicit field if needed, then implement the scope-preservation/enforcement fix from finding #1 in the same patch.

## 3. Webhook subscriptions are a stored SSRF primitive

**Severity:** Critical in cloud/internal-network deployments — stored SSRF.
**Status:** Open.

**Impact:** Any write-scoped tenant user can create a webhook pointing at loopback, link-local metadata services, private RFC1918 addresses, Kubernetes service DNS, or internal admin panels. Later event dispatch makes the server POST attacker-influenced payloads to that URL. There is no scheme restriction, private-address guard, DNS rebinding protection, redirect policy, or reuse of the hardened ingest URL validator.

**Evidence:**

- `WebhookCreate.url` is an unconstrained string.
- `create_webhook` stores `body.url` directly.
- `dispatch_webhooks` later calls `httpx.AsyncClient(...).post(sub.url, ...)`.

**Exploit sketch:** Register `http://169.254.169.254/latest/meta-data/...`, `http://127.0.0.1:...`, or an internal service URL as a webhook. Trigger any matching event and observe the delivery outcome/timing/status; if response bodies are later logged or surfaced this can become data exfiltration.

**Recommended fix:** Apply the same URL policy used for ingest fetches to webhook targets at creation and immediately before dispatch; block private/loopback/link-local/reserved/multicast targets and unsafe schemes; disable redirects or validate every redirect hop; consider egress allowlists for webhooks.

## 4. Malware preview/download routes break tenant isolation and expose unauthenticated malware metadata/raw previews

**Severity:** Critical — cross-tenant data exposure; unauthenticated sensitive-content access.
**Status:** Open.

**Impact:** `GET /api/v1/malware/{entity_id}/info` and `/raw` are public and load entities by global UUID with no tenant predicate. Anyone who knows or guesses an entity UUID can access malware metadata and a hex/ASCII preview. `/download` requires `write`, but still loads by global UUID with no tenant predicate, so any write-scoped user can download malware from another tenant.

**Evidence:**

- `malware_info` and `malware_raw_view` have the auth dependencies commented out.
- `_get_malware_entity` queries `select(Entity).where(Entity.id == eid)` with no `tenant_id` filter.
- `malware_download` requires `Scope.write`, but calls the same tenant-unscoped `_get_malware_entity` helper.

**Exploit sketch:** Use a leaked UUID from logs, search results, exports, browser history, or another endpoint, then call `/api/v1/malware/<uuid>/raw` without credentials to retrieve the preview. With any write API key, call `/download` for cross-tenant malware content.

**Recommended fix:** Require `Scope.read` for `info`/`raw`, require `Scope.write` or a dedicated malware-download scope for `download`, and change `_get_malware_entity` to require `auth.tenant_id` unless the caller is superadmin.

## 5. Malware local-file lookup uses database-controlled paths without destination-boundary checks

**Severity:** Critical if an attacker can create or poison malware-style entity `external_refs` — local file read / sensitive file disclosure.
**Status:** Open.

**Impact:** `_locate_standalone` and `_locate_binary` build paths from `repo_name`, `repo_path`, and `file_path` stored in `Entity.external_refs`. The resulting path is not resolved and checked to remain under the intended repository root. For standalone files, an entity with `source` beginning `malware-repo`, empty/absent SHA256, and `file_path` containing `../` can cause the service to read files outside the malware repository. Public `/raw` then returns a preview and `/info` returns hashes/metadata; `/download` can return full contents to any write-scoped caller. Current first-party entity creation does not expose `external_refs`, but corpus/import/backfill pipelines and database poisoning make this a high-impact unsafe primitive.

**Evidence:**

- `_locate_standalone` computes `full_path = base / file_path` and reads it without `resolve()`/relative-to validation.
- `_locate_binary` computes `zip_path = base / repo_path` and opens it without boundary validation.
- SHA256 verification is skipped unless `sha256` is present and length 64.

**Recommended fix:** Resolve `base`, `repo`, and target paths; reject paths outside the repo root; reject absolute paths and `..` components before filesystem access; require a valid SHA256 for malware entities before serving bytes; keep `/raw` preview size bounded and authenticated per finding #4.

## 6. API-key-to-JWT exchange issues unusable bearer tokens

**Severity:** Critical functional bug for API-key token exchange — auth flow broken for clients using `/auth/token`.
**Status:** Open.

**Impact:** `/api/v1/auth/token` signs a JWT with `sub` set to the API key's tenant ID, not a user ID. `_resolve_bearer` interprets `sub` as a user ID and queries `User.id == sub`. Unless a user UUID coincidentally equals the tenant UUID, the bearer token produced by `/auth/token` cannot authenticate to protected endpoints. The route also omits the API key's scopes from the token model, so even a corrected subject needs a clear policy for user-bound and tenant-only keys.

**Evidence:**

- `get_token` creates `create_access_token({"sub": str(api_key.tenant_id), "tenant_id": str(api_key.tenant_id)})`.
- `_resolve_bearer` reads `payload.get("sub")` as `user_id` and requires a matching active approved `User` row.

**Recommended fix:** For user-bound API keys, sign `sub=user_id`, include `tenant_id`, and derive scopes from the backing key or user role. For tenant-only keys, either keep API-key auth only or implement a distinct tenant-token resolver. Add tests for `/auth/token` followed by `/auth/me` or another protected read endpoint.

## 7. Read-scoped lookup paths mutate tenant data and trigger paid/external enrichment

**Severity:** High-to-critical depending on provider quotas and data-integrity requirements — read/write boundary violation and quota exhaustion.
**Status:** Open.

**Impact:** `POST /api/v1/lookup` and MCP `lookup_ioc` require only read scope, but both can create entities, update dispatch state, and trigger enrichment providers. This lets read-only credentials write to the corpus and spend provider quota/API budget. The issue is especially risky through MCP SSE because finding #1 already widens write capability.

**Evidence:**

- `lookup` calls `auth.require_scope(Scope.read)` only.
- It then calls `_upsert_entity`, commits the new entity, records dispatch state, and queues `_dispatch_enrichment`.
- MCP `lookup_ioc` is registered with `scope="read"`, but it also calls `_upsert_entity`, `_record_dispatch`, and `_dispatch_enrichment`.

**Recommended fix:** Split lookup into read-only cache/classification and write/enrich variants; require `Scope.write` for entity creation and `Scope.enrichment` for provider dispatch/forced repoll; add separate safe read endpoints for cached results only.

## Priority remediation order

1. Fix MCP SSE `AuthContext` construction and scope enforcement together (#1 and #2).
2. Lock down unauthenticated/tenant-unscoped malware routes and add path-boundary validation (#4 and #5).
3. Add webhook URL validation and dispatch-time redirect/IP checks (#3).
4. Fix `/auth/token` semantics and tests (#6).
5. Reclassify lookup/enrichment side effects under write/enrichment scopes (#7).
