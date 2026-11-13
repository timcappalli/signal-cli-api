async function loadSpec() {
  const container = document.getElementById("endpoints");
  try {
    const res = await fetch("/openapi.json");
    const spec = await res.json();
    if (spec.info) {
      document.getElementById("api-title").textContent = spec.info.title || "Signal CLI REST API";
      document.getElementById("api-desc").textContent = spec.info.description || "";
    }
    const paths = spec.paths || {};
    Object.keys(paths).forEach(pathStr => {
      const methods = paths[pathStr];
      Object.keys(methods).forEach(method => {
        const op = methods[method];
        const card = document.createElement("div");
        card.className = "endpoint";

        const header = document.createElement("div");
        header.className = "ep-header";

        const badge = document.createElement("span");
        badge.className = "method method-" + method.toLowerCase();
        badge.textContent = method;

        const pathEl = document.createElement("span");
        pathEl.className = "path";
        pathEl.textContent = pathStr;

        const sumEl = document.createElement("span");
        sumEl.className = "summary";
        sumEl.textContent = op.summary || "";

        header.append(badge, pathEl, sumEl);
        card.appendChild(header);

        if (op.description) {
          const desc = document.createElement("div");
          desc.className = "desc";
          desc.textContent = op.description;
          card.appendChild(desc);
        }

        if (op.requestBody || op.parameters) {
          const pre = document.createElement("pre");
          pre.textContent = JSON.stringify({
            parameters: op.parameters,
            requestBody: op.requestBody
          }, null, 2);
          card.appendChild(pre);
        }

        container.appendChild(card);
      });
    });
  } catch (err) {
    container.textContent = "Failed to load /openapi.json";
  }
}
window.addEventListener("DOMContentLoaded", loadSpec);
