// Keep the API key strictly in page memory; never persist to storage.
let explorerToken = "";

function setExplorerToken(val) {
  explorerToken = (val || "").trim();
  const statusEl = document.getElementById("auth-status");
  if (!statusEl) return;
  if (explorerToken) {
    const prefix = explorerToken.length > 10 ? explorerToken.slice(0, 8) + "..." : "configured";
    statusEl.textContent = "Key active in memory (" + prefix + ")";
    statusEl.className = "auth-status active";
  } else {
    statusEl.textContent = "No key set (memory-only)";
    statusEl.className = "auth-status";
  }
}

window.addEventListener("pagehide", () => {
  explorerToken = "";
  const input = document.getElementById("apiKeyInput");
  if (input) input.value = "";
});

function resolveRef(spec, obj) {
  if (!obj || typeof obj !== "object") return obj;
  if (!obj.$ref || typeof obj.$ref !== "string" || !obj.$ref.startsWith("#/")) {
    return obj;
  }
  const parts = obj.$ref
    .slice(2)
    .split("/")
    .map(p => p.replace(/~1/g, "/").replace(/~0/g, "~"));
  let cur = spec;
  for (const part of parts) {
    if (cur && typeof cur === "object" && part in cur) {
      cur = cur[part];
    } else {
      return obj;
    }
  }
  return cur;
}

function buildFieldInput(name, prop, isRequired) {
  const group = document.createElement("div");
  group.className = "field-group";

  const label = document.createElement("label");
  label.className = "field-label";
  label.textContent = name;
  if (isRequired) {
    const req = document.createElement("span");
    req.className = "field-req";
    req.textContent = "*";
    label.appendChild(req);
  }
  group.appendChild(label);

  const schemaType = prop.type || "string";
  let inputEl;

  if (schemaType === "boolean") {
    const checkLabel = document.createElement("label");
    checkLabel.className = "field-check";
    inputEl = document.createElement("input");
    inputEl.type = "checkbox";
    if (prop.default === true) inputEl.checked = true;
    const span = document.createElement("span");
    span.textContent = prop.description || "true / false";
    checkLabel.append(inputEl, span);
    group.appendChild(checkLabel);
  } else if (Array.isArray(prop.enum)) {
    inputEl = document.createElement("select");
    const emptyOpt = document.createElement("option");
    emptyOpt.value = "";
    emptyOpt.textContent = "-- select --";
    inputEl.appendChild(emptyOpt);
    prop.enum.forEach(v => {
      const opt = document.createElement("option");
      opt.value = v;
      opt.textContent = v;
      inputEl.appendChild(opt);
    });
    group.appendChild(inputEl);
  } else if (schemaType === "integer" || schemaType === "number") {
    inputEl = document.createElement("input");
    inputEl.type = "number";
    inputEl.placeholder = prop.example !== undefined ? String(prop.example) : (prop.description || "");
    if (prop.minimum !== undefined) inputEl.min = String(prop.minimum);
    if (prop.maximum !== undefined) inputEl.max = String(prop.maximum);
    group.appendChild(inputEl);
  } else if (name === "message" || name === "avatar") {
    inputEl = document.createElement("textarea");
    inputEl.placeholder = prop.example !== undefined ? String(prop.example) : (prop.description || "");
    group.appendChild(inputEl);
  } else {
    inputEl = document.createElement("input");
    inputEl.type = name === "admin_key" ? "password" : "text";
    if (name === "admin_key") {
      inputEl.autocomplete = "off";
    }
    if (schemaType === "array") {
      const ex = Array.isArray(prop.example) ? prop.example.join(", ") : "";
      inputEl.placeholder = ex ? "comma-separated, e.g. " + ex : "comma-separated values";
    } else {
      inputEl.placeholder = prop.example !== undefined ? String(prop.example) : (prop.description || "");
    }
    group.appendChild(inputEl);
  }

  return { group, inputEl, schemaType };
}

function buildTryPanel(spec, pathStr, method, op) {
  const panel = document.createElement("div");
  panel.className = "try-panel";

  const grid = document.createElement("div");
  grid.className = "try-grid";

  const pathInputs = [];
  const params = Array.isArray(op.parameters) ? op.parameters : [];
  params.forEach(rawParam => {
    const param = resolveRef(spec, rawParam);
    if (param && param.in === "path") {
      const schema = param.schema || { type: "string" };
      const prop = {
        type: schema.type || "string",
        description: param.description || "",
        example: param.example || schema.example
      };
      const { group, inputEl } = buildFieldInput(param.name, prop, Boolean(param.required));
      grid.appendChild(group);
      pathInputs.push({ name: param.name, required: Boolean(param.required), inputEl });
    }
  });

  const bodyInputs = [];
  const reqBody = resolveRef(spec, op.requestBody);
  const jsonContent = reqBody && reqBody.content && reqBody.content["application/json"];
  const bodySchema = jsonContent && resolveRef(spec, jsonContent.schema);
  if (bodySchema && bodySchema.properties) {
    const reqSet = new Set(Array.isArray(bodySchema.required) ? bodySchema.required : []);
    Object.keys(bodySchema.properties).forEach(propName => {
      const prop = resolveRef(spec, bodySchema.properties[propName]) || {};
      const { group, inputEl, schemaType } = buildFieldInput(propName, prop, reqSet.has(propName));
      grid.appendChild(group);
      bodyInputs.push({ name: propName, schemaType, required: reqSet.has(propName), inputEl });
    });
  }

  if (grid.children.length > 0) {
    panel.appendChild(grid);
  }

  const footer = document.createElement("div");
  footer.className = "try-footer";

  const execBtn = document.createElement("button");
  execBtn.type = "button";
  execBtn.className = "btn-primary";
  execBtn.textContent = "Execute " + method.toUpperCase();
  footer.appendChild(execBtn);

  const note = document.createElement("span");
  note.style.fontSize = "12px";
  note.style.color = "var(--text-muted)";
  if (Array.isArray(op.security) && op.security.length === 0) {
    note.textContent = "Public endpoint (no auth required)";
  } else {
    note.textContent = "Uses Authorization: Bearer key from top bar";
  }
  footer.appendChild(note);
  panel.appendChild(footer);

  const respBox = document.createElement("div");
  respBox.className = "resp-box";

  const respMeta = document.createElement("div");
  respMeta.className = "resp-meta";
  const statusPill = document.createElement("span");
  statusPill.className = "status-pill";
  const timingEl = document.createElement("span");
  timingEl.style.color = "var(--text-muted)";
  const useTokenBtn = document.createElement("button");
  useTokenBtn.type = "button";
  useTokenBtn.className = "btn-secondary";
  useTokenBtn.style.padding = "3px 8px";
  useTokenBtn.style.fontSize = "11px";
  useTokenBtn.style.marginLeft = "auto";
  useTokenBtn.style.display = "none";
  useTokenBtn.textContent = "Use token in Explorer";
  respMeta.append(statusPill, timingEl, useTokenBtn);

  const respPre = document.createElement("pre");
  respBox.append(respMeta, respPre);
  panel.appendChild(respBox);

  execBtn.addEventListener("click", async () => {
    let targetPath = pathStr;
    for (const p of pathInputs) {
      const val = p.inputEl.value.trim();
      if (p.required && !val) {
        statusPill.className = "status-pill status-err";
        statusPill.textContent = "Validation Error";
        timingEl.textContent = "";
        respPre.textContent = "Missing required path parameter: " + p.name;
        respBox.classList.add("open");
        return;
      }
      targetPath = targetPath.replace("{" + p.name + "}", encodeURIComponent(val));
    }

    const headers = {};
    const requiresAuth = !(Array.isArray(op.security) && op.security.length === 0);
    const inputVal = (document.getElementById("apiKeyInput")?.value || "").trim();
    const activeToken = inputVal || explorerToken;
    if (requiresAuth && activeToken) {
      headers["Authorization"] = "Bearer " + activeToken;
    }

    const fetchOpts = { method: method.toUpperCase(), headers };

    if (bodySchema) {
      const payload = {};
      for (const f of bodyInputs) {
        if (f.schemaType === "boolean") {
          if (f.inputEl.checked) {
            payload[f.name] = true;
          }
          continue;
        }
        const raw = f.inputEl.value.trim();
        if (!raw) {
          if (f.required) {
            statusPill.className = "status-pill status-err";
            statusPill.textContent = "Validation Error";
            timingEl.textContent = "";
            respPre.textContent = "Missing required field: " + f.name;
            respBox.classList.add("open");
            return;
          }
          continue;
        }
        if (f.schemaType === "integer" || f.schemaType === "number") {
          const num = Number(raw);
          if (Number.isNaN(num)) {
            statusPill.className = "status-pill status-err";
            statusPill.textContent = "Validation Error";
            timingEl.textContent = "";
            respPre.textContent = "Field '" + f.name + "' must be a valid number.";
            respBox.classList.add("open");
            return;
          }
          payload[f.name] = num;
        } else if (f.schemaType === "array") {
          if (raw.startsWith("[")) {
            try {
              payload[f.name] = JSON.parse(raw);
            } catch (_) {
              statusPill.className = "status-pill status-err";
              statusPill.textContent = "Validation Error";
              timingEl.textContent = "";
              respPre.textContent = "Invalid JSON array in field '" + f.name + "'.";
              respBox.classList.add("open");
              return;
            }
          } else {
            payload[f.name] = raw.split(",").map(s => s.trim()).filter(Boolean);
          }
        } else {
          payload[f.name] = raw;
        }
      }
      headers["Content-Type"] = "application/json";
      fetchOpts.body = JSON.stringify(payload);
    }

    execBtn.disabled = true;
    const started = performance.now();
    try {
      const res = await fetch(targetPath, fetchOpts);
      const elapsed = Math.round(performance.now() - started);
      const text = await res.text();
      let formatted = text;
      let parsedJson = null;
      if (text) {
        try {
          parsedJson = JSON.parse(text);
          formatted = JSON.stringify(parsedJson, null, 2);
        } catch (_) {}
      } else {
        formatted = "(empty response body)";
      }

      if (res.ok && parsedJson && typeof parsedJson.token === "string" && parsedJson.token) {
        const returnedToken = parsedJson.token;
        useTokenBtn.style.display = "inline-block";
        useTokenBtn.onclick = () => {
          const input = document.getElementById("apiKeyInput");
          if (input) input.value = returnedToken;
          setExplorerToken(returnedToken);
          useTokenBtn.textContent = "Applied!";
          setTimeout(() => { useTokenBtn.textContent = "Use token in Explorer"; }, 1500);
        };
      } else {
        useTokenBtn.style.display = "none";
      }

      statusPill.className = "status-pill " + (res.ok ? "status-ok" : "status-err");
      statusPill.textContent = res.status + " " + res.statusText;
      timingEl.textContent = elapsed + " ms";
      respPre.textContent = formatted;
      respBox.classList.add("open");
    } catch (err) {
      statusPill.className = "status-pill status-err";
      statusPill.textContent = "Network Error";
      timingEl.textContent = "";
      respPre.textContent = String(err);
      respBox.classList.add("open");
    } finally {
      execBtn.disabled = false;
    }
  });

  return panel;
}

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

        const actions = document.createElement("div");
        actions.className = "ep-actions";
        const tryBtn = document.createElement("button");
        tryBtn.type = "button";
        tryBtn.className = "btn-secondary";
        tryBtn.style.padding = "5px 10px";
        tryBtn.style.fontSize = "12px";
        tryBtn.textContent = "Try it out";
        actions.appendChild(tryBtn);

        header.append(badge, pathEl, sumEl, actions);
        card.appendChild(header);

        if (op.description) {
          const desc = document.createElement("div");
          desc.className = "desc";
          desc.textContent = op.description;
          card.appendChild(desc);
        }

        const tryPanel = buildTryPanel(spec, pathStr, method, op);
        tryBtn.addEventListener("click", () => {
          const isOpen = tryPanel.classList.toggle("open");
          tryBtn.textContent = isOpen ? "Hide" : "Try it out";
        });
        card.appendChild(tryPanel);

        if (op.requestBody || op.parameters) {
          const details = document.createElement("details");
          details.className = "schema-details";
          const summary = document.createElement("summary");
          summary.textContent = "View OpenAPI Schema";
          const pre = document.createElement("pre");
          pre.textContent = JSON.stringify({
            parameters: op.parameters,
            requestBody: resolveRef(spec, op.requestBody)
          }, null, 2);
          details.append(summary, pre);
          card.appendChild(details);
        }

        container.appendChild(card);
      });
    });
  } catch (err) {
    container.textContent = "Failed to load /openapi.json";
  }
}

window.addEventListener("DOMContentLoaded", () => {
  const apiKeyInput = document.getElementById("apiKeyInput");
  const toggleBtn = document.getElementById("toggleKeyVisBtn");
  const clearBtn = document.getElementById("clearKeyBtn");

  if (apiKeyInput) {
    apiKeyInput.addEventListener("input", () => setExplorerToken(apiKeyInput.value));
  }
  if (toggleBtn && apiKeyInput) {
    toggleBtn.addEventListener("click", () => {
      const hidden = apiKeyInput.type === "password";
      apiKeyInput.type = hidden ? "text" : "password";
      toggleBtn.textContent = hidden ? "Hide" : "Show";
    });
  }
  if (clearBtn && apiKeyInput) {
    clearBtn.addEventListener("click", () => {
      apiKeyInput.value = "";
      apiKeyInput.type = "password";
      if (toggleBtn) toggleBtn.textContent = "Show";
      setExplorerToken("");
    });
  }

  loadSpec();
});
