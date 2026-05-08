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

  // ---------------------------------------------------------------------------
  // Enrichment card rendering — per-provider rich layouts
  // ---------------------------------------------------------------------------

  function renderEnrichmentItem(item) {
    const d = item.data || {};
    const hasData = d && Object.keys(d).length > 0 && !d.not_found;
    const providerIcons = {
      virustotal:  "🦠", greynoise: "🔇", shodan: "🔍", ipinfo: "📍",
      bgp_he:      "🌐", mitre_attack: "⚔️", nvd: "🛡", crowdstrike: "🦅",
      misp: "🔗", opencti: "🕵️",
    };
    const icon = providerIcons[item.source] || "🔌";
    const cachedBadge = item.expired
      ? `<span class="tiny-pill" style="background:rgba(255,100,50,0.18);color:#f87">⏰ expired</span>`
      : `<span class="tiny-pill" style="opacity:.5">cached</span>`;

    let body = "";
    if (!hasData) {
      body = `<p class="subtle" style="margin-top:.5rem;font-style:italic;">No data returned${item.success ? "" : " (provider error)"}.</p>`;
    } else if (item.source === "virustotal") {
      const stats = [
        ["malicious",  d.malicious,  "#f44"],
        ["suspicious", d.suspicious, "#fb6"],
        ["harmless",   d.harmless,   "#4c4"],
        ["undetected", d.undetected, "#888"],
      ];
      const detScore = (d.malicious ?? 0) + (d.suspicious ?? 0);
      body = `
        <div style="margin:.6rem 0;display:flex;gap:.6rem;flex-wrap:wrap;">
          ${stats.map(([k,v,c]) => `<span style="background:rgba(0,0,0,.25);border-radius:.5rem;padding:.25rem .6rem;color:${c};">${k}: <b>${v ?? 0}</b></span>`).join("")}
        </div>
        <div class="grid-2" style="gap:.5rem;margin-top:.5rem;">
          ${d.country    ? `<div class="grid-card" style="padding:.5rem .75rem;"><small>Country</small><div>${escapeHtml(d.country)}</div></div>` : ""}
          ${d.asn        ? `<div class="grid-card" style="padding:.5rem .75rem;"><small>ASN</small><div>${escapeHtml(String(d.asn))}</div></div>` : ""}
          ${d.as_owner   ? `<div class="grid-card" style="padding:.5rem .75rem;"><small>AS Owner</small><div>${escapeHtml(d.as_owner)}</div></div>` : ""}
          ${d.network    ? `<div class="grid-card" style="padding:.5rem .75rem;"><small>Network</small><div>${escapeHtml(d.network)}</div></div>` : ""}
          ${d.reputation != null ? `<div class="grid-card" style="padding:.5rem .75rem;"><small>Reputation</small><div style="color:${d.reputation>0?'#4c4':d.reputation<0?'#f44':'#aaa'}">${d.reputation}</div></div>` : ""}
        </div>
        ${d.tags?.length ? `<div style="margin-top:.4rem;">${d.tags.map(t=>`<span class="tiny-pill">${escapeHtml(t)}</span>`).join(" ")}</div>` : ""}
        ${d.vt_link     ? `<a class="button-muted" href="${escapeHtml(d.vt_link)}" target="_blank" rel="noopener" style="margin-top:.6rem;display:inline-block;">View on VirusTotal ↗</a>` : ""}
      `;
    } else if (item.source === "greynoise") {
      const cls = d.classification === "malicious" ? "#f44" : d.classification === "benign" ? "#4c4" : "#aaa";
      body = `
        <div style="margin:.4rem 0;display:flex;gap:.5rem;flex-wrap:wrap;">
          <span class="tiny-pill" style="color:${cls};">${escapeHtml(d.classification || "unknown")}</span>
          ${d.noise   ? `<span class="tiny-pill">📡 noise</span>` : ""}
          ${d.riot    ? `<span class="tiny-pill" style="color:#4c4;">✅ riot (trusted infra)</span>` : ""}
        </div>
        ${d.name       ? `<p style="margin:.3rem 0;"><b>${escapeHtml(d.name)}</b></p>` : ""}
        ${d.last_seen  ? `<p class="subtle">Last seen: ${escapeHtml(d.last_seen)}</p>` : ""}
        ${d.link       ? `<a class="button-muted" href="${escapeHtml(d.link)}" target="_blank" rel="noopener" style="margin-top:.4rem;display:inline-block;">GreyNoise ↗</a>` : ""}
      `;
    } else if (item.source === "shodan") {
      body = `
        <div class="grid-2" style="gap:.4rem;margin:.4rem 0;">
          ${d.org     ? `<div class="grid-card" style="padding:.4rem .6rem;"><small>Org</small><div>${escapeHtml(d.org)}</div></div>` : ""}
          ${d.country ? `<div class="grid-card" style="padding:.4rem .6rem;"><small>Country</small><div>${escapeHtml(d.country)}</div></div>` : ""}
        </div>
        ${d.ports?.length   ? `<p style="margin:.3rem 0;">Ports: ${d.ports.map(p=>`<span class="mono">${p}</span>`).join(", ")}</p>` : ""}
        ${d.hostnames?.length ? `<p class="subtle">Hostnames: ${d.hostnames.slice(0,5).map(h=>escapeHtml(h)).join(", ")}</p>` : ""}
        ${d.tags?.length    ? `<div>${d.tags.map(t=>`<span class="tiny-pill">${escapeHtml(t)}</span>`).join(" ")}</div>` : ""}
      `;
    } else if (item.source === "ipinfo") {
      body = `
        <div class="grid-2" style="gap:.4rem;margin:.4rem 0;">
          ${d.city     ? `<div class="grid-card" style="padding:.4rem .6rem;"><small>City</small><div>${escapeHtml(d.city)}, ${escapeHtml(d.region||"")}</div></div>` : ""}
          ${d.country  ? `<div class="grid-card" style="padding:.4rem .6rem;"><small>Country</small><div>${escapeHtml(d.country)}</div></div>` : ""}
          ${d.org      ? `<div class="grid-card" style="padding:.4rem .6rem;"><small>Org</small><div>${escapeHtml(d.org)}</div></div>` : ""}
          ${d.hostname ? `<div class="grid-card" style="padding:.4rem .6rem;"><small>rDNS</small><div>${escapeHtml(d.hostname)}</div></div>` : ""}
        </div>
        ${d.latitude && d.longitude ? `<p class="subtle">Coords: ${d.latitude}, ${d.longitude}</p>` : ""}
      `;
    } else if (item.source === "bgp_he") {
      const asn = d.asn_detail || {};
      const routes = d.routes || [];
      const prefixCount = asn.prefix_count_v4 || 0;
      const peerCount   = asn.peer_count || 0;
      const asnNum      = d.origin_asn || asn.asn || "";
      body = `
        <div class="grid-2" style="gap:.4rem;margin:.4rem 0;">
          ${d.containing_prefix ? `<div class="grid-card" style="padding:.4rem .6rem;"><small>Containing Prefix</small><div class="mono">${escapeHtml(d.containing_prefix)}</div></div>` : ""}
          ${d.origin_asn ? `<div class="grid-card" style="padding:.4rem .6rem;"><small>Origin AS</small><div class="mono">AS${escapeHtml(String(d.origin_asn))}</div></div>` : ""}
        </div>
        ${asn.name ? `<p style="margin:.3rem 0;"><b>${escapeHtml(asn.name)}</b></p>` : ""}
        ${prefixCount ? `<p class="subtle">Advertised prefixes: ${prefixCount} v4 · ${asn.prefix_count_v6 || 0} v6 · ${peerCount} peers</p>` : ""}
        ${routes.slice(0,6).map(r=>`<div style="font-size:.8rem;opacity:.8;" class="mono">${escapeHtml(r.prefix)} via AS${escapeHtml(String(r.origin_asn))} — ${escapeHtml(r.description)}</div>`).join("")}
        ${asnNum ? `<a class="button-muted" href="https://bgp.he.net/AS${escapeHtml(String(asnNum))}" target="_blank" rel="noopener" style="margin-top:.5rem;display:inline-block;">bgp.he.net ↗</a>` : ""}
      `;
    } else {
      // Generic fallback — show non-empty fields
      const entries = Object.entries(d).filter(([,v]) => v != null && v !== "" && !(Array.isArray(v) && v.length === 0));
      body = entries.length
        ? `<dl style="margin:.4rem 0;display:grid;grid-template-columns:auto 1fr;gap:.15rem .75rem;">
            ${entries.slice(0,20).map(([k,v]) => `<dt class="subtle" style="white-space:nowrap;">${escapeHtml(k)}</dt><dd class="mono" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(Array.isArray(v)?v.join(", "):String(v)).slice(0,120)}</dd>`).join("")}
           </dl>`
        : `<p class="subtle" style="margin-top:.5rem;font-style:italic;">No data returned.</p>`;
    }

    return `
      <article class="result-card${!hasData ? ' result-card--empty' : ''}">
        <div style="display:flex;justify-content:space-between;gap:1rem;align-items:center;flex-wrap:wrap;">
          <h3 style="display:flex;align-items:center;gap:.4rem;">${icon} ${escapeHtml(item.source)}</h3>
          <div style="display:flex;gap:.4rem;align-items:center;">${cachedBadge}</div>
        </div>
        ${body}
      </article>
    `;
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

    const allEnrichments = payload.enrichments || [];
    const richEnrichments = allEnrichments.filter(e => e.data && Object.keys(e.data).length > 0);
    const emptyEnrichments = allEnrichments.filter(e => !e.data || Object.keys(e.data).length === 0);

    enrichments.innerHTML = richEnrichments.length
      ? richEnrichments.map(renderEnrichmentItem).join("") +
        (emptyEnrichments.length
          ? `<details style="margin-top:.75rem;"><summary class="subtle" style="cursor:pointer;">${emptyEnrichments.length} providers returned no data</summary><div style="display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.4rem;">${emptyEnrichments.map(e=>`<span class="tiny-pill" style="opacity:.6;">${escapeHtml(e.source)}</span>`).join("")}</div></details>`
          : "")
      : (allEnrichments.length
          ? `<div class='empty-state'>Enrichment is running — ${allEnrichments.length} providers queried, no results yet.</div>`
          : "<div class='empty-state'>No enrichment results yet. Polling is still running.</div>");

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
      // Clear thinking placeholder on error
      const placeholder = document.querySelector(".thinking-placeholder");
      if (placeholder) placeholder.remove();
      setStatus(error.message, "error", "lookup-status");
    }
  }

  async function loadEntity(entityId) {
    state.entityId = entityId;
    hideGraphContextMenu();
    await pollEntity(entityId);
  }

  function setLookupBusy(form, busy) {
    const btn = form.querySelector("[type='submit']");
    if (!btn) return;
    if (busy) {
      btn.disabled = true;
      btn.dataset.originalText = btn.textContent;
      btn.textContent = "Looking up…";
    } else {
      btn.disabled = false;
      btn.textContent = btn.dataset.originalText || "Run Lookup";
    }
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

    setLookupBusy(form, true);
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

      // Reveal and scroll to results panel immediately
      const resultsPanel = document.getElementById("results-panel");
      resultsPanel?.removeAttribute("hidden");
      resultsPanel?.scrollIntoView({ behavior: "smooth", block: "start" });

      // Show "Thinking…" placeholder while enrichment is in-flight
      document.getElementById("entity-summary").innerHTML = `
        <div class="empty-state thinking-placeholder">
          <div class="thinking-dots">
            <span></span><span></span><span></span>
          </div>
          <p class="subtle" style="margin-top:0.75rem;">Enriching <span class="mono">${escapeHtml(payload.entity_value || payload.entity_id || input.value.trim())}</span> — this may take a few seconds.</p>
        </div>
      `;
      document.getElementById("enrichment-list").innerHTML = "";

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
    } finally {
      setLookupBusy(form, false);
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
