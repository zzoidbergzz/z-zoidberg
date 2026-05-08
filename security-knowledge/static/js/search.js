(() => {
  const input = document.querySelector("[data-search-input]") || document.getElementById("search-input");
  const chip = document.querySelector("[data-detected-type]") || document.getElementById("detected-type");

  if (!input || !chip || !window.ZjeIndicator) return;

  const render = () => {
    const classified = window.ZjeIndicator.classify(input.value);
    const raw = input.value.trim();
    const wasNormalized = raw && classified.value && classified.value !== raw;
    chip.textContent = classified.type === "empty" ? "paste an indicator" : wasNormalized ? `${classified.type} · cleaned` : classified.type;
    chip.dataset.type = classified.type;
    chip.title = wasNormalized ? `Normalized to ${classified.value}` : "";
  };

  input.addEventListener("input", render);
  render();
})();
