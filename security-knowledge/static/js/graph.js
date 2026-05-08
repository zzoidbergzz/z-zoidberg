window.ZjeGraph = (() => {
  const palette = {
    ip: { background: "#6bf2c7", border: "#1f8f71" },
    domain: { background: "#f0b45f", border: "#9b6b26" },
    url: { background: "#96c3ff", border: "#3569a8" },
    email: { background: "#ff9bb0", border: "#99455b" },
    asn: { background: "#cdb6ff", border: "#6a51a2" },
    default: { background: "#dbe8ef", border: "#6d8ea2" },
  };

  function render(containerId, graph) {
    const container = document.getElementById(containerId);
    if (!container) return;
    if (!window.vis || !graph?.nodes?.length) {
      container.innerHTML = "<div class='empty-state'>No graph data yet.</div>";
      return;
    }
    const nodes = graph.nodes.map((node) => ({
      ...node,
      shape: "dot",
      size: 18,
      font: { color: "#ecf4f8", face: "IBM Plex Mono", size: 14 },
      color: palette[node.type] || palette.default,
    }));
    const edges = graph.edges.map((edge) => ({
      from: edge.from,
      to: edge.to,
      label: edge.relation,
      color: { color: "rgba(143, 178, 199, 0.5)" },
      font: { color: "#8fb2c7", face: "IBM Plex Mono", size: 10, strokeWidth: 0 },
      smooth: { type: "continuous" },
    }));
    const nodeData = new vis.DataSet(nodes);
    const edgeData = new vis.DataSet(edges);
    const network = new vis.Network(
      container,
      { nodes: nodeData, edges: edgeData },
      {
        autoResize: true,
        interaction: { hover: true, multiselect: true, navigationButtons: true },
        physics: {
          stabilization: false,
          barnesHut: { springLength: 145, springConstant: 0.03 },
        },
      }
    );
    network.on("click", (params) => {
      if (!params.nodes?.length) return;
      const node = nodeData.get(params.nodes[0]);
      window.dispatchEvent(new CustomEvent("zje:graph-select", { detail: node }));
    });
    network.on("oncontext", (params) => {
      params.event.preventDefault();
      const nodeId = params.nodes?.[0];
      if (!nodeId) { window.dispatchEvent(new CustomEvent("zje:graph-context-hide")); return; }
      const node = nodeData.get(nodeId);
      window.dispatchEvent(new CustomEvent("zje:graph-context", {
        detail: { node, x: params.event.srcEvent.clientX, y: params.event.srcEvent.clientY },
      }));
    });
    return network;
  }

  return { render };
})();
