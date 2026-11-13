let sessionToken = sessionStorage.getItem("signal_admin_session") || "";
let sessionExpiry = parseInt(sessionStorage.getItem("signal_admin_expiry") || "0", 10);
let timerInterval = null;
let lastActivity = Date.now();
let selectedAvatarDataUrl = "";
const INACTIVITY_TIMEOUT_MS = 2 * 60 * 1000; // 2 minutes inactivity timeout
const MAX_AVATAR_BYTES = 3 * 1024 * 1024; // 3 MB

// User activity listeners for inactivity timeout
["mousedown", "keydown", "scroll", "touchstart"].forEach(evt => {
  window.addEventListener(evt, () => { lastActivity = Date.now(); }, { passive: true });
});

window.addEventListener("DOMContentLoaded", () => {
  const loginForm = document.getElementById("login-form");
  if (loginForm) {
    loginForm.addEventListener("submit", handleLogin);
  }

  const profileForm = document.getElementById("profile-form");
  if (profileForm) {
    profileForm.addEventListener("submit", handleUpdateProfile);
  }

  const avatarInput = document.getElementById("avatarInput");
  if (avatarInput) {
    avatarInput.addEventListener("change", handleAvatarSelected);
  }

  const clearAvatarBtn = document.getElementById("clear-avatar-btn");
  if (clearAvatarBtn) {
    clearAvatarBtn.addEventListener("click", clearAvatarSelection);
  }

  const createKeyForm = document.getElementById("create-key-form");
  if (createKeyForm) {
    createKeyForm.addEventListener("submit", handleCreateKey);
  }

  const logoutBtn = document.getElementById("logout-btn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", () => logout(true));
  }

  const copyKeyBtn = document.getElementById("copy-key-btn");
  if (copyKeyBtn) {
    copyKeyBtn.addEventListener("click", copyCreatedKey);
  }

  const refreshKeysBtn = document.getElementById("refresh-keys-btn");
  if (refreshKeysBtn) {
    refreshKeysBtn.addEventListener("click", loadKeys);
  }

  if (sessionToken && sessionExpiry && Date.now() < sessionExpiry) {
    startSessionTimer();
    showDashboard();
  } else {
    showLogin();
  }
});

function showLogin() {
  stopSessionTimer();
  document.getElementById("login-section").style.display = "block";
  document.getElementById("dashboard-section").style.display = "none";
  document.getElementById("logout-btn-container").style.display = "none";
  document.getElementById("session-timer-badge").style.display = "none";
}

function showDashboard() {
  document.getElementById("login-section").style.display = "none";
  document.getElementById("dashboard-section").style.display = "block";
  document.getElementById("logout-btn-container").style.display = "inline-block";
  document.getElementById("session-timer-badge").style.display = "inline-flex";
  loadKeys();
  loadAccountsList();
}

async function handleLogin(e) {
  e.preventDefault();
  const keyInput = document.getElementById("adminKeyInput");
  const key = keyInput.value.trim();
  const errEl = document.getElementById("login-error");
  const alertEl = document.getElementById("session-alert");
  errEl.style.display = "none";
  alertEl.style.display = "none";

  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ admin_key: key })
    });

    if (res.ok) {
      const data = await res.json();
      sessionToken = data.token;
      const ttlMs = (data.expires_in || 180) * 1000;
      sessionExpiry = Date.now() + ttlMs;

      sessionStorage.setItem("signal_admin_session", sessionToken);
      sessionStorage.setItem("signal_admin_expiry", sessionExpiry.toString());

      keyInput.value = "";
      lastActivity = Date.now();
      startSessionTimer();
      showDashboard();
    } else {
      const errData = await res.json().catch(() => ({}));
      errEl.textContent = errData.error || "Invalid API_KEY_MGMT root admin key.";
      errEl.style.display = "block";
    }
  } catch (err) {
    errEl.textContent = "Error connecting to server.";
    errEl.style.display = "block";
  }
}

function startSessionTimer() {
  stopSessionTimer();
  updateTimerDisplay();

  timerInterval = setInterval(() => {
    const now = Date.now();
    if (now - lastActivity > INACTIVITY_TIMEOUT_MS) {
      expireSession("Session locked due to 2 minutes of inactivity. Please re-authenticate.");
      return;
    }

    if (now >= sessionExpiry) {
      expireSession("Your 3-minute admin session has expired. Please re-authenticate.");
      return;
    }

    updateTimerDisplay();
  }, 1000);
}

function stopSessionTimer() {
  if (timerInterval) {
    clearInterval(timerInterval);
    timerInterval = null;
  }
}

function updateTimerDisplay() {
  const remainingSec = Math.max(0, Math.floor((sessionExpiry - Date.now()) / 1000));
  const mins = Math.floor(remainingSec / 60);
  const secs = remainingSec % 60;
  const formatted = String(mins).padStart(2, "0") + ":" + String(secs).padStart(2, "0");

  const cdEl = document.getElementById("session-countdown");
  const badgeEl = document.getElementById("session-timer-badge");
  if (cdEl) cdEl.textContent = formatted;

  if (badgeEl) {
    badgeEl.className = "session-badge";
    if (remainingSec <= 30) {
      badgeEl.classList.add("session-critical");
    } else if (remainingSec <= 60) {
      badgeEl.classList.add("session-warning");
    } else {
      badgeEl.classList.add("session-normal");
    }
  }
}

function expireSession(message) {
  logout(false);
  const alertEl = document.getElementById("session-alert");
  alertEl.textContent = message || "Session expired. Please re-authenticate.";
  alertEl.style.display = "block";
}

async function logout(callApi = true) {
  if (callApi && sessionToken) {
    try {
      await fetch("/api/auth/logout", {
        method: "POST",
        headers: { "Authorization": "Bearer " + sessionToken }
      });
    } catch (_) {}
  }

  sessionToken = "";
  sessionExpiry = 0;
  sessionStorage.removeItem("signal_admin_session");
  sessionStorage.removeItem("signal_admin_expiry");
  document.getElementById("adminKeyInput").value = "";
  showLogin();
}

async function loadAccountsList() {
  const datalist = document.getElementById("known-accounts-list");
  if (!datalist) return;
  try {
    const res = await fetch("/v1/accounts", {
      headers: { "Authorization": "Bearer " + sessionToken }
    });
    if (!res.ok) return;
    const accounts = await res.json();
    datalist.textContent = "";
    if (Array.isArray(accounts)) {
      accounts.forEach(acc => {
        const opt = document.createElement("option");
        opt.value = acc;
        datalist.appendChild(opt);
      });
      const profileAccInput = document.getElementById("profileAccountInput");
      if (profileAccInput && !profileAccInput.value && accounts.length === 1) {
        profileAccInput.value = accounts[0];
      }
    }
  } catch (_) {}
}

function handleAvatarSelected(e) {
  const file = e.target.files && e.target.files[0];
  const preview = document.getElementById("avatar-preview");
  const clearBtn = document.getElementById("clear-avatar-btn");
  const statusEl = document.getElementById("profile-status");
  if (statusEl) statusEl.style.display = "none";

  if (!file) {
    clearAvatarSelection();
    return;
  }

  if (file.size > MAX_AVATAR_BYTES) {
    showProfileStatus("Selected photo exceeds the 3 MB maximum size.", true);
    clearAvatarSelection();
    return;
  }

  const reader = new FileReader();
  reader.onload = () => {
    selectedAvatarDataUrl = typeof reader.result === "string" ? reader.result : "";
    if (preview && selectedAvatarDataUrl) {
      preview.src = selectedAvatarDataUrl;
      preview.style.display = "block";
    }
    if (clearBtn) {
      clearBtn.style.display = "inline-flex";
    }
  };
  reader.readAsDataURL(file);
}

function clearAvatarSelection() {
  selectedAvatarDataUrl = "";
  const avatarInput = document.getElementById("avatarInput");
  const preview = document.getElementById("avatar-preview");
  const clearBtn = document.getElementById("clear-avatar-btn");
  if (avatarInput) avatarInput.value = "";
  if (preview) {
    preview.removeAttribute("src");
    preview.style.display = "none";
  }
  if (clearBtn) clearBtn.style.display = "none";
}

function showProfileStatus(msg, isError) {
  const statusEl = document.getElementById("profile-status");
  if (!statusEl) return;
  statusEl.textContent = msg;
  statusEl.className = "status-banner " + (isError ? "status-error" : "status-success");
  statusEl.style.display = "block";
}

async function handleUpdateProfile(e) {
  e.preventDefault();
  const account = document.getElementById("profileAccountInput").value.trim();
  const givenName = document.getElementById("givenNameInput").value.trim();
  const familyName = document.getElementById("familyNameInput").value.trim();
  const submitBtn = document.getElementById("save-profile-btn");

  if (!account || !givenName) {
    showProfileStatus("Account and First Name are required.", true);
    return;
  }

  const payload = {
    account: account,
    given_name: givenName,
    family_name: familyName
  };
  if (selectedAvatarDataUrl) {
    payload.avatar = selectedAvatarDataUrl;
  }

  if (submitBtn) submitBtn.disabled = true;
  showProfileStatus("Updating Signal profile...", false);

  try {
    const res = await fetch("/api/accounts/profile", {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + sessionToken,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    if (res.ok) {
      showProfileStatus("Account profile updated successfully.", false);
      clearAvatarSelection();
    } else if (res.status === 401) {
      expireSession("Session expired. Please re-authenticate.");
    } else {
      const errData = await res.json().catch(() => ({}));
      showProfileStatus(errData.error || "Failed to update account profile.", true);
    }
  } catch (err) {
    showProfileStatus("Network error while updating profile.", true);
  } finally {
    if (submitBtn) submitBtn.disabled = false;
  }
}

async function loadKeys() {
  const tbody = document.getElementById("keys-table-body");
  const emptyState = document.getElementById("empty-state");
  tbody.textContent = "";
  const loadingRow = document.createElement("tr");
  const loadingCell = document.createElement("td");
  loadingCell.colSpan = 7;
  loadingCell.style.textAlign = "center";
  loadingCell.textContent = "Loading...";
  loadingRow.appendChild(loadingCell);
  tbody.appendChild(loadingRow);

  try {
    const res = await fetch("/api/keys", {
      headers: { "Authorization": "Bearer " + sessionToken }
    });
    if (!res.ok) {
      if (res.status === 401) {
        expireSession("Session expired on server. Please re-authenticate.");
      }
      return;
    }
    const keys = await res.json();
    tbody.textContent = "";

    if (!keys || keys.length === 0) {
      emptyState.style.display = "block";
      return;
    }

    emptyState.style.display = "none";
    keys.forEach(k => {
      const tr = document.createElement("tr");
      const dateStr = k.created_at ? new Date(k.created_at).toLocaleString() : "N/A";
      const lastUsedStr = k.last_used_at ? new Date(k.last_used_at).toLocaleString() : "Never";
      const accountsStr = Array.isArray(k.accounts) && k.accounts.length ? k.accounts.join(", ") : "none";
      const permsStr = Array.isArray(k.permissions) && k.permissions.length ? k.permissions.join(", ") : "none";

      const tdName = document.createElement("td");
      tdName.style.fontWeight = "500";
      tdName.textContent = k.name || "";

      const tdPrefix = document.createElement("td");
      const spanPrefix = document.createElement("span");
      spanPrefix.className = "token-preview";
      spanPrefix.textContent = k.prefix || "sig_****";
      tdPrefix.appendChild(spanPrefix);

      const tdAccounts = document.createElement("td");
      const spanAccounts = document.createElement("span");
      spanAccounts.className = "token-preview";
      spanAccounts.textContent = accountsStr;
      tdAccounts.appendChild(spanAccounts);

      const tdPerms = document.createElement("td");
      const spanPerms = document.createElement("span");
      spanPerms.className = "token-preview";
      spanPerms.textContent = permsStr;
      tdPerms.appendChild(spanPerms);

      const tdDate = document.createElement("td");
      tdDate.style.color = "var(--text-muted)";
      tdDate.style.fontSize = "13px";
      tdDate.textContent = dateStr;

      const tdLastUsed = document.createElement("td");
      tdLastUsed.style.color = k.last_used_at ? "var(--text)" : "var(--text-muted)";
      tdLastUsed.style.fontSize = "13px";
      tdLastUsed.textContent = lastUsedStr;

      const tdAction = document.createElement("td");
      tdAction.style.textAlign = "right";
      const revokeBtn = document.createElement("button");
      revokeBtn.type = "button";
      revokeBtn.className = "btn-danger";
      revokeBtn.textContent = "Revoke";
      revokeBtn.addEventListener("click", () => revokeKey(k.id, k.name));
      tdAction.appendChild(revokeBtn);

      tr.append(tdName, tdPrefix, tdAccounts, tdPerms, tdDate, tdLastUsed, tdAction);
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.textContent = "";
    const errRow = document.createElement("tr");
    const errCell = document.createElement("td");
    errCell.colSpan = 7;
    errCell.style.textAlign = "center";
    errCell.style.color = "var(--danger)";
    errCell.textContent = "Failed to load keys";
    errRow.appendChild(errCell);
    tbody.appendChild(errRow);
  }
}

async function handleCreateKey(e) {
  e.preventDefault();
  const nameInput = document.getElementById("serviceNameInput");
  const accountsInput = document.getElementById("accountsInput");
  const expiresDaysInput = document.getElementById("expiresDaysInput");
  const name = nameInput.value.trim();
  const accounts = accountsInput.value.split(",").map(s => s.trim()).filter(Boolean);
  const expiresDaysRaw = expiresDaysInput ? expiresDaysInput.value.trim() : "";
  const permissions = [];
  if (document.getElementById("permSend").checked) permissions.push("send");
  if (document.getElementById("permReceive").checked) permissions.push("receive");
  if (document.getElementById("permAdmin").checked) permissions.push("admin");

  if (!name || accounts.length === 0 || permissions.length === 0) {
    alert("Name, at least one account, and at least one permission are required.");
    return;
  }

  const payload = { name: name, accounts: accounts, permissions: permissions };
  if (expiresDaysRaw !== "") {
    const days = parseInt(expiresDaysRaw, 10);
    if (isNaN(days) || days <= 0) {
      alert("Expires in days must be a positive integer.");
      return;
    }
    payload.expires_in_days = days;
  }

  try {
    const res = await fetch("/api/keys", {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + sessionToken,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    if (res.ok) {
      const newKey = await res.json();
      nameInput.value = "";
      accountsInput.value = "";
      if (expiresDaysInput) expiresDaysInput.value = "";
      displayCreatedKey(newKey.key);
      loadKeys();
    } else if (res.status === 401) {
      expireSession("Session expired. Please re-authenticate.");
    } else {
      const errData = await res.json().catch(() => ({}));
      alert(errData.error || "Failed to create key");
    }
  } catch (err) {
    alert("Network error creating key");
  }
}

function displayCreatedKey(key) {
  const alertBox = document.getElementById("new-key-alert");
  const textEl = document.getElementById("created-key-text");
  textEl.textContent = key;
  alertBox.style.display = "block";
  alertBox.scrollIntoView({ behavior: "smooth" });
}

function copyCreatedKey() {
  const text = document.getElementById("created-key-text").textContent;
  navigator.clipboard.writeText(text).then(() => {
    alert("API Key copied to clipboard!");
  });
}

async function revokeKey(id, name) {
  if (!confirm(`Are you sure you want to revoke key for '${name}'? Any service using this key will be disconnected.`)) {
    return;
  }

  try {
    const res = await fetch("/api/keys/" + encodeURIComponent(id), {
      method: "DELETE",
      headers: { "Authorization": "Bearer " + sessionToken }
    });
    if (res.ok) {
      loadKeys();
    } else if (res.status === 401) {
      expireSession("Session expired. Please re-authenticate.");
    } else {
      alert("Failed to revoke key");
    }
  } catch (err) {
    alert("Error revoking key");
  }
}
