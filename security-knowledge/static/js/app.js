window.ZjeApp = (() => {
  const state = {
    entityId: null,
    currentEntity: null,
    selectedGraphNode: null,
    graphContextNode: null,
    bulkPreview: null,
    lookupDispatchMode: null,
    lookupPollCount: 0,
    pollTimer: null,
  };

  function setStatus(message, kind = "info", targetId = "global-status") {
    const el = document.getElementById(targetId);
    if (!el) return;
    el.textContent = message || "";
    el.dataset.kind = kind;
  }

  async function parseResponse(response) {
    const contentType = response.headers.get("content-type") || "";
    const payload = contentType.includes("application/json") ? await response.json() : await response.text();
    if (!response.ok) {
      throw new Error(typeof payload === "string" ? payload : payload.detail || "Request failed");
    }
    return payload;
  }

  async function api(url, options = {}) {
    const response = await fetch(url, {
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
      ...options,
    });
    return parseResponse(response);
  }

  function prettify(data) {
    return JSON.stringify(data, null, 2);
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  }

  function analyzeBulkInput(rawText) {
    const indicator = window.ZjeIndicator;
    const lines = String(rawText || "").split(/\r?\n/);
    const entries = [];
    const seen = new Map();
    let normalizedCount = 0;

    lines.forEach((line, index) => {
      const original = line.trim();
      if (!original) return;
      const classified = indicator ? indicator.classify(original) : { type: "unknown", value: original };
      const key = `${classified.type}:${classified.value}`;
      const firstLine = seen.get(key) || null;
      if (!firstLine) {
        seen.set(key, index + 1);
      }
      if (classified.value !== original) {
        normalizedCount += 1;
      }
      entries.push({
        lineNumber: index + 1,
        original,
        normalized: classified.value,
        type: classified.type,
        isDuplicate: Boolean(firstLine),
        duplicateOf: firstLine,
      });
    });

    return {
      entries,
      totalLines: entries.length,
      uniqueCount: seen.size,
      duplicateCount: entries.filter((entry) => entry.isDuplicate).length,
      unknownCount: entries.filter((entry) => !entry.isDuplicate && entry.type === "unknown").length,
      normalizedCount,
    };
  }

  function renderBulkPreview(rawText = "") {
    const container = document.getElementById("bulk-lookup-preview");
    const submitButton = document.querySelector("[data-bulk-submit]");
    if (!container) return;

    const preview = analyzeBulkInput(rawText);
    state.bulkPreview = preview;

    if (!preview.totalLines) {
      container.innerHTML = "<div class='empty-state'>Paste a batch to see normalized values, duplicate collapse, and detected indicator types before dispatch.</div>";
      if (submitButton) submitButton.disabled = false;
      return;
    }

    const showing = preview.entries.slice(0, 12);
    container.innerHTML = `
      <div class="bulk-preview-grid">
        <div class="bulk-preview-stat">
          <div class="subtle">non-empty lines</div>
          <strong>${preview.totalLines}</strong>
        </div>
        <div class="bulk-preview-stat">
          <div class="subtle">unique normalized</div>
          <strong>${preview.uniqueCount}</strong>
        </div>
        <div class="bulk-preview-stat">
          <div class="subtle">duplicates collapsed</div>
          <strong>${preview.duplicateCount}</strong>
        </div>
        <div class="bulk-preview-stat">
          <div class="subtle">unknown indicators</div>
          <strong>${preview.unknownCount}</strong>
        </div>
      </div>
      <div class="result-list">
        ${showing.map((entry) => `
          <article class="result-card">
            <div class="bulk-preview-line">
              <div>
                <div class="subtle">line ${entry.lineNumber}</div>
                <div class="mono" style="margin-top:0.4rem;">${escapeHtml(entry.original)}</div>
                ${entry.normalized !== entry.original ? `<div class="subtle mono" style="margin-top:0.45rem;">normalized → ${escapeHtml(entry.normalized)}</div>` : ""}
              </div>
              <div class="bulk-preview-meta">
                <span class="tiny-pill">${escapeHtml(entry.type)}</span>
                ${entry.normalized !== entry.original ? "<span class='tiny-pill warn'>cleaned</span>" : ""}
                ${entry.isDuplicate ? `<span class="tiny-pill danger">dup of line ${entry.duplicateOf}</span>` : ""}
              </div>
            </div>
          </article>
        `).join("")}
      </div>
      ${preview.entries.length > showing.length ? `<p class="subtle">Showing first ${showing.length} preview rows.</p>` : ""}
      <p class="subtle">Batch requests accept up to 100 unique normalized indicators.</p>
    `;

    if (submitButton) {
      submitButton.disabled = preview.uniqueCount > 100;
    }
  }

  function renderGraphSelection() {
    const container = document.getElementById("graph-selection");
    if (!container) return;
    if (!state.selectedGraphNode) {
      container.innerHTML = "Click a node in the graph to select it for pathing or pivot review.";
      return;
    }
    container.innerHTML = `
      <div class="section-title">${escapeHtml(state.selectedGraphNode.label)}</div>
      <p class="subtle" style="margin-top:0.55rem;">Node ID <span class="mono">${escapeHtml(state.selectedGraphNode.id)}</span></p>
      <p class="subtle" style="margin-top:0.35rem;">Type ${escapeHtml(state.selectedGraphNode.type)}</p>
      <div style="display:flex;gap:0.75rem;flex-wrap:wrap;margin-top:0.9rem;">
        <button class="button-muted" type="button" data-path-fill="source">Use as Source</button>
        <button class="button-muted" type="button" data-path-fill="target">Use as Target</button>
        <button class="button" type="button" data-pivot-selected>Load Node Results</button>
      </div>
    `;
  }

  function hideGraphContextMenu() {
    const menu = document.getElementById("graph-context-menu");
    if (!menu) return;
    menu.hidden = true;
    state.graphContextNode = null;
  }

  function showGraphContextMenu(detail) {
    const menu = document.getElementById("graph-context-menu");
    if (!menu || !detail?.node) return;
    state.graphContextNode = detail.node;
    document.getElementById("graph-context-title").textContent = detail.node.label || detail.node.id;
    document.getElementById("graph-context-meta").textContent = `${detail.node.type} · ${detail.node.id}`;
    menu.style.left = `${Math.min(detail.x, window.innerWidth - 240)}px`;
    menu.style.top = `${Math.min(detail.y, window.innerHeight - 220)}px`;
    menu.hidden = false;
  }

  function setPathField(kind, value) {
    const form = document.querySelector("[data-path-form]");
    const input = form?.querySelector(`[name='${kind}_entity_id']`);
    if (input) input.value = value || "";
  }

  function renderResults(payload) {
    const resultsPanel = document.getElementById("results-panel");
    const summary = document.getElementById("entity-summary");
    const enrichments = document.getElementById("enrichment-list");
    const links = document.getElementById("export-links");
    const relationships = document.getElementById("relationship-list");
    if (!resultsPanel || !summary || !enrichments || !links || !relationships) return;

    resultsPanel.hidden = false;
    const entity = payload.entity || {};
    state.currentEntity = entity;
    if (entity.id) state.entityId = entity.id;
    summary.innerHTML = `
      <div class="grid-2">
        <div class="grid-card">
          <div class="tiny-pill">${escapeHtml(entity.entity_type || "unknown")}</div>
          <div class="metric" style="margin-top:0.75rem;">${escapeHtml(entity.entity_value || "pending")}</div>
          <p class="subtle" style="margin-top:0.55rem;">Entity ID <span class="mono">${escapeHtml(entity.id || state.entityId || "pending")}</span></p>
        </div>
        <div class="grid-card">
          <div class="section-title">Analyst Notes</div>
          <p class="subtle" style="margin-top:0.55rem;">${escapeHtml(entity.notes || "No notes saved.")}</p>
          <p class="subtle" style="margin-top:0.75rem;">Tags: ${escapeHtml((entity.tags || []).join(", ") || "none")}</p>
        </div>
      </div>
    `;

    enrichments.innerHTML = payload.enrichments?.length
      ? payload.enrichments
          .map(
            (item) => {
              const screenshot = item.data?.static_url
                ? `
                  <div style="margin-top:0.9rem;">
                    <img src="${escapeHtml(item.data.static_url)}" alt="Captured screenshot for ${escapeHtml(item.source)}" style="width:100%;border-radius:0.9rem;border:1px solid rgba(123,161,181,0.18);" loading="lazy">
                  </div>
                `
                : "";
              return `
                <article class="result-card">
                  <div style="display:flex;justify-content:space-between;gap:1rem;align-items:center;">
                    <h3>${escapeHtml(item.source)}</h3>
                    <span class="tiny-pill">${escapeHtml(item.query_duration_ms ?? "?")}ms</span>
                  </div>
                  ${screenshot}
                  <pre>${escapeHtml(prettify(item.data))}</pre>
                </article>
              `;
            }
          )
          .join("")
      : "<div class='empty-state'>No enrichment results yet. Polling is still running.</div>";

    relationships.innerHTML = payload.relationships?.length
      ? payload.relationships
          .slice(0, 50)
          .map(
            (item) => `
              <tr>
                <td>${escapeHtml(item.relation_type)}</td>
                <td class="mono">${escapeHtml(item.target_entity)}</td>
                <td>${escapeHtml(item.discovered_via || "n/a")}</td>
              </tr>
            `
          )
          .join("")
      : "<tr><td colspan='3' class='subtle'>No relationships extracted yet.</td></tr>";

    const id = entity.id || state.entityId;
    links.innerHTML = id
      ? `
        <a class="button-muted" href="/api/v1/lookup/entity/${id}/export?format=json">JSON</a>
        <a class="button-muted" href="/api/v1/lookup/entity/${id}/export?format=markdown">Markdown</a>
        <a class="button-muted" href="/api/v1/lookup/entity/${id}/export?format=csv">CSV</a>
        <a class="button-muted" href="/api/v1/lookup/entity/${id}/export?format=pdf">PDF</a>
      `
      : "";

    if (entity.id) {
      const pathForm = document.querySelector("[data-path-form]");
      const sourceField = pathForm?.querySelector("[name='source_entity_id']");
      if (sourceField && !sourceField.value) {
        sourceField.value = entity.id;
      }
    }
  }

  async function loadGraph(entityId) {
    try {
      const graph = await api(`/api/v1/lookup/entity/${entityId}/graph`);
      window.ZjeGraph?.render("graph-stage", graph);
    } catch (error) {
      setStatus(error.message, "error", "lookup-status");
    }
  }

  async function pollEntity(entityId) {
    try {
      const payload = await api(`/api/v1/lookup/entity/${entityId}/results`);
      renderResults(payload);
      await loadGraph(entityId);
      if (payload.enrichments?.length) {
        clearInterval(state.pollTimer);
        state.pollTimer = null;
        state.lookupPollCount = 0;
        setStatus("Results updated.", "success", "lookup-status");
      } else {
        state.lookupPollCount += 1;
        if (state.lookupDispatchMode === "celery") {
          setStatus(
            state.lookupPollCount > 3
              ? "Queued to Celery. Still waiting on a worker or provider responses."
              : "Queued to Celery. Waiting for worker results.",
            "info",
            "lookup-status"
          );
        } else if (state.lookupDispatchMode === "in_process") {
          setStatus("Enrichment is running in-process. Waiting for results.", "info", "lookup-status");
        } else if (state.lookupDispatchMode === "debounced") {
          setStatus("A recent lookup is already in flight. Waiting for those results instead of sending another dispatch.", "info", "lookup-status");
        }
      }
    } catch (error) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
      state.lookupPollCount = 0;
      setStatus(error.message, "error", "lookup-status");
    }
  }

  async function loadEntity(entityId) {
    state.entityId = entityId;
    hideGraphContextMenu();
    await pollEntity(entityId);
  }

  async function handleLookupSubmit(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const input = form.querySelector("[name='query']");
    const investigation = form.querySelector("[name='investigation_id']");
    const forceRepoll = form.querySelector("[name='force_repoll']")?.checked || false;
    if (!input?.value.trim()) {
      setStatus("Paste an indicator first.", "error", "lookup-status");
      return;
    }

    setStatus(forceRepoll ? "Submitting manual repoll request." : "Checking cache state and dispatch eligibility.", "info", "lookup-status");
    try {
      const payload = await api("/api/v1/lookup", {
        method: "POST",
        body: JSON.stringify({
          query: input.value,
          investigation_id: investigation?.value || null,
          force_repoll: forceRepoll,
        }),
      });
      document.getElementById("results-panel")?.removeAttribute("hidden");
      document.getElementById("entity-summary").innerHTML = `
        <div class="empty-state">
          <div class="section-title">Lookup accepted</div>
          <p class="subtle" style="margin-top:0.55rem;">${escapeHtml(payload.message)}. Entity <span class="mono">${escapeHtml(payload.entity_id || "n/a")}</span>, type <span class="mono">${escapeHtml(payload.entity_type)}</span>.</p>
        </div>
      `;
      if (payload.cached_results?.length) {
        renderResults({ entity: { id: payload.entity_id, entity_type: payload.entity_type, entity_value: payload.entity_value }, enrichments: payload.cached_results, relationships: [] });
      }
      if (state.pollTimer) {
        clearInterval(state.pollTimer);
        state.pollTimer = null;
      }
      if (payload.entity_id) {
        state.lookupDispatchMode = payload.dispatch_mode || null;
        state.lookupPollCount = 0;
        await loadEntity(payload.entity_id);
        if (payload.should_poll) {
          state.pollTimer = setInterval(() => pollEntity(payload.entity_id), 2500);
        }
      }
      const modeText = payload.dispatch_mode ? ` Mode: ${payload.dispatch_mode}.` : "";
      const repollText = payload.next_repoll_at ? ` Next repoll window: ${payload.next_repoll_at}.` : "";
      setStatus(`${payload.message}${modeText}${repollText}`, "success", "lookup-status");
    } catch (error) {
      setStatus(error.message, "error", "lookup-status");
    }
  }

  async function handleBulkLookupSubmit(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const body = Object.fromEntries(new FormData(form).entries());
    const resultsEl = document.getElementById("bulk-lookup-results");
    const preview = state.bulkPreview || analyzeBulkInput(body.query_blob || "");
    if (!preview.totalLines) {
      setStatus("Paste at least one indicator first.", "error", "bulk-lookup-status");
      return;
    }
    if (preview.uniqueCount > 100) {
      setStatus("Bulk lookup supports up to 100 unique normalized indicators.", "error", "bulk-lookup-status");
      return;
    }
    setStatus("Dispatching batch lookup.", "info", "bulk-lookup-status");
    try {
      const payload = await api("/api/v1/lookup/bulk", {
        method: "POST",
        body: JSON.stringify(body),
      });
      resultsEl.innerHTML = payload.results.map((item) => `
        <article class="result-card">
          <div style="display:flex;justify-content:space-between;gap:1rem;align-items:center;">
            <h3>${escapeHtml(item.original_query)}</h3>
            <span class="tiny-pill ${item.skipped_duplicate ? "warn" : item.entity_type === "unknown" ? "danger" : ""}">${escapeHtml(item.entity_type)}</span>
          </div>
          <p class="subtle" style="margin-top:0.55rem;">${escapeHtml(item.message)}</p>
          ${item.normalized_query && item.normalized_query !== item.original_query.trim() ? `<p class="subtle mono" style="margin-top:0.55rem;">normalized → ${escapeHtml(item.normalized_query)}</p>` : ""}
          <p class="subtle mono" style="margin-top:0.55rem;">${escapeHtml(item.entity_id || "no entity")}</p>
        </article>
      `).join("");
      setStatus(
        `Queued ${payload.queued_count} lookups. Reused cache for ${payload.reused_cache_count || 0}, suppressed ${payload.suppressed_dispatch_count || 0}, skipped ${payload.duplicate_count} duplicates, ${payload.unknown_count} unknown, normalized ${payload.normalized_count}.`,
        "success",
        "bulk-lookup-status"
      );
    } catch (error) {
      setStatus(error.message, "error", "bulk-lookup-status");
    }
  }

  async function handlePathSubmit(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const source = form.querySelector("[name='source_entity_id']")?.value.trim();
    const target = form.querySelector("[name='target_entity_id']")?.value.trim();
    const resultsEl = document.getElementById("path-results");
    if (!source || !target) {
      setStatus("Provide both source and target entity ids.", "error", "path-status");
      return;
    }
    setStatus("Resolving graph path.", "info", "path-status");
    try {
      const payload = await api(`/api/v1/lookup/path?source_entity_id=${encodeURIComponent(source)}&target_entity_id=${encodeURIComponent(target)}`);
      if (!payload.path?.length) {
        resultsEl.innerHTML = "<div class='empty-state'>No pivot path found between those entities.</div>";
        setStatus(payload.message || "No path found.", "error", "path-status");
        return;
      }
      resultsEl.innerHTML = `
        <article class="result-card">
          <div class="section-title">Shortest Path (${payload.length} hops)</div>
          <div style="display:grid;gap:0.65rem;margin-top:1rem;">
            ${payload.path.map((node, index) => `
              <div>
                <span class="tiny-pill">${escapeHtml(node.type)}</span>
                <div class="mono" style="margin-top:0.35rem;">${escapeHtml(node.id)}</div>
                <div>${escapeHtml(node.value)}</div>
                ${payload.edges[index] ? `<div class="subtle" style="margin-top:0.35rem;">via ${escapeHtml(payload.edges[index].relations.join(", "))}</div>` : ""}
              </div>
            `).join("")}
          </div>
        </article>
      `;
      setStatus("Path resolved.", "success", "path-status");
    } catch (error) {
      setStatus(error.message, "error", "path-status");
    }
  }

  async function loadHistoryVersions() {
    const source = document.getElementById("history-source")?.value.trim();
    const entityId = state.currentEntity?.id || state.entityId;
    const container = document.getElementById("history-versions");
    if (!entityId || !source) {
      setStatus("Load an entity and provide an enrichment source first.", "error", "history-status");
      return;
    }
    setStatus("Loading enrichment versions.", "info", "history-status");
    try {
      const payload = await api(`/api/v1/lookup/entity/${entityId}/history/versions?source=${encodeURIComponent(source)}&limit=10`);
      container.innerHTML = payload.versions.length ? payload.versions.map((version) => `
        <article class="result-card">
          <div style="display:flex;justify-content:space-between;gap:1rem;align-items:center;">
            <h3>${escapeHtml(version.source)}</h3>
            <span class="tiny-pill">${version.is_current ? "current" : "history"}</span>
          </div>
          <p class="subtle mono" style="margin-top:0.55rem;">${escapeHtml(version.id)}</p>
          <p class="subtle" style="margin-top:0.35rem;">${escapeHtml(version.queried_at)}</p>
        </article>
      `).join("") : "<div class='empty-state'>No versions stored for that source yet.</div>";
      setStatus("Version history loaded.", "success", "history-status");
    } catch (error) {
      setStatus(error.message, "error", "history-status");
    }
  }

  async function loadLatestDiff() {
    const source = document.getElementById("history-source")?.value.trim();
    const entityId = state.currentEntity?.id || state.entityId;
    const container = document.getElementById("history-diff");
    if (!entityId || !source) {
      setStatus("Load an entity and provide an enrichment source first.", "error", "history-status");
      return;
    }
    setStatus("Computing latest diff.", "info", "history-status");
    try {
      const payload = await api(`/api/v1/lookup/entity/${entityId}/diff?source=${encodeURIComponent(source)}`);
      const summary = payload.diff?.summary || { total: 0, added: 0, removed: 0, modified: 0 };
      const changes = payload.diff?.changes || [];
      container.innerHTML = `
        <article class="result-card">
          <div class="section-title">Diff Summary</div>
          <p class="subtle" style="margin-top:0.55rem;">Total ${summary.total} · added ${summary.added} · removed ${summary.removed} · modified ${summary.modified}</p>
          <div class="result-list" style="margin-top:1rem;">
            ${changes.length ? changes.map((change) => `
              <div class="result-card">
                <div style="display:flex;justify-content:space-between;gap:1rem;align-items:center;">
                  <strong>${escapeHtml(change.path)}</strong>
                  <span class="tiny-pill">${escapeHtml(change.change_type)}</span>
                </div>
                <pre>${escapeHtml(prettify({ old: change.old, new: change.new, old_count: change.old_count, new_count: change.new_count }))}</pre>
              </div>
            `).join("") : "<div class='empty-state'>No differences found or insufficient history.</div>"}
          </div>
        </article>
      `;
      setStatus("Diff loaded.", "success", "history-status");
    } catch (error) {
      setStatus(error.message, "error", "history-status");
    }
  }

  async function handleGraphContextAction(action) {
    const node = state.graphContextNode || state.selectedGraphNode;
    if (!node) return;
    if (action === "pivot") {
      await loadEntity(node.id);
      return;
    }
    if (action === "source") {
      setPathField("source", node.id);
      hideGraphContextMenu();
      return;
    }
    if (action === "target") {
      setPathField("target", node.id);
      hideGraphContextMenu();
      return;
    }
    if (action === "copy") {
      await navigator.clipboard.writeText(node.id);
      setStatus("Entity id copied.", "success", "path-status");
      hideGraphContextMenu();
    }
  }

  async function handleRegister(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const body = Object.fromEntries(new FormData(form).entries());
    setStatus("Creating account.", "info", "auth-status");
    try {
      const result = await api("/auth/register", { method: "POST", body: JSON.stringify(body) });
      setStatus(result.message + (result.api_key ? " API key shown below." : ""), "success", "auth-status");
      const keyBox = document.getElementById("one-time-api-key");
      if (keyBox && result.api_key) {
        keyBox.hidden = false;
        keyBox.textContent = result.api_key;
      }
      form.reset();
    } catch (error) {
      setStatus(error.message, "error", "auth-status");
    }
  }

  async function handleLogin(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const body = Object.fromEntries(new FormData(form).entries());
    setStatus("Opening session.", "info", "auth-status");
    try {
      const result = await api("/auth/login", { method: "POST", body: JSON.stringify(body) });
      setStatus(`Welcome back ${result.user.name}. Redirecting.`, "success", "auth-status");
      window.setTimeout(() => {
        window.location.href = "/";
      }, 700);
    } catch (error) {
      setStatus(error.message, "error", "auth-status");
    }
  }

  function init() {
    document.querySelector("[data-lookup-form]")?.addEventListener("submit", handleLookupSubmit);
    document.querySelector("[data-bulk-lookup-form]")?.addEventListener("submit", handleBulkLookupSubmit);
    document.querySelector("[data-bulk-lookup-form] [name='query_blob']")?.addEventListener("input", (event) => {
      renderBulkPreview(event.target.value);
    });
    document.querySelector("[data-path-form]")?.addEventListener("submit", handlePathSubmit);
    document.querySelector("[data-register-form]")?.addEventListener("submit", handleRegister);
    document.querySelector("[data-login-form]")?.addEventListener("submit", handleLogin);
    document.querySelector("[data-use-current-root]")?.addEventListener("click", () => {
      if (state.currentEntity?.id || state.entityId) setPathField("source", state.currentEntity?.id || state.entityId);
    });
    document.querySelector("[data-history-load]")?.addEventListener("click", loadHistoryVersions);
    document.querySelector("[data-history-diff]")?.addEventListener("click", loadLatestDiff);
    window.addEventListener("zje:graph-select", (event) => {
      state.selectedGraphNode = event.detail;
      renderGraphSelection();
    });
    window.addEventListener("zje:graph-context", (event) => {
      state.selectedGraphNode = event.detail.node;
      renderGraphSelection();
      showGraphContextMenu(event.detail);
    });
    window.addEventListener("zje:graph-context-hide", hideGraphContextMenu);
    document.addEventListener("click", async (event) => {
      if (event.target.matches("[data-path-fill='source']")) {
        setPathField("source", state.selectedGraphNode?.id);
      }
      if (event.target.matches("[data-path-fill='target']")) {
        setPathField("target", state.selectedGraphNode?.id);
      }
      if (event.target.matches("[data-pivot-selected]")) {
        if (state.selectedGraphNode?.id) {
          await loadEntity(state.selectedGraphNode.id);
        }
      }
      if (event.target.matches("[data-context-action]")) {
        await handleGraphContextAction(event.target.dataset.contextAction);
        return;
      }
      if (!event.target.closest("#graph-context-menu")) {
        hideGraphContextMenu();
      }
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") hideGraphContextMenu();
    });
    renderBulkPreview(document.querySelector("[data-bulk-lookup-form] [name='query_blob']")?.value || "");
    renderGraphSelection();
  }

  return { init, api, setStatus, loadEntity };
})();

window.addEventListener("DOMContentLoaded", () => window.ZjeApp.init());
