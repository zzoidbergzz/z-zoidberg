window.ZjeIndicator = (() => {
  function normalize(raw) {
    let value = String(raw || "").trim();
    if (!value) return "";
    value = value.replace(/^hxxps/i, "https");
    value = value.replace(/^hxxp/i, "http");
    value = value.replace(/[\[\(\{]\s*([.:/@])\s*[\]\)\}]/g, "$1");
    value = value.replace(/[\[\(\{]\s*dot\s*[\]\)\}]/gi, ".");
    value = value.replace(/[\[\(\{]\s*at\s*[\]\)\}]/gi, "@");
    return value.trim();
  }

  function classify(raw) {
    const value = normalize(raw);
    const normalizedDomain = value.replace(/\.+$/, "").toLowerCase();
    if (!value) return { type: "empty", value: "" };
    if (/^https?:\/\//i.test(value)) return { type: "url", value };
    if (/^[a-f0-9]{64}$/i.test(value)) return { type: "sha256", value: value.toLowerCase() };
    if (/^[a-f0-9]{40}$/i.test(value)) return { type: "sha1", value: value.toLowerCase() };
    if (/^[a-f0-9]{32}$/i.test(value)) return { type: "md5", value: value.toLowerCase() };
    if (/^AS\d+$/i.test(value)) return { type: "asn", value: value.toUpperCase() };
    if (/^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$/i.test(value)) return { type: "email", value: value.toLowerCase() };
    if (/^([a-z0-9]([a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}$/i.test(normalizedDomain)) {
      return { type: "domain", value: normalizedDomain };
    }
    if (/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(value) || /^[0-9a-f:]+\/?\d*$/i.test(value) && value.includes(":")) {
      return { type: "ip/cidr", value };
    }
    if (/^\+?\d{7,15}$/.test(value.replace(/[\s\-().]/g, ""))) {
      return { type: "phone", value: value.replace(/[\s\-().]/g, "") };
    }
    if (/^@?[a-z0-9_]{3,30}$/i.test(value)) return { type: "username", value: value.replace(/^@/, "").toLowerCase() };
    if (value.includes(":") || value.split(".").length === 4) return { type: "ip/cidr", value };
    return { type: "unknown", value };
  }

  return { normalize, classify };
})();
