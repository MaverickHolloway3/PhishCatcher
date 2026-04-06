(function () {
  "use strict";

  const STORAGE_KEYS = {
    safe: "safeDomains",
    blocked: "blockedDomains",
    safeEnabled: "safeListEnabled",
    blockedEnabled: "blockedListEnabled",
  };

  const safeInput = document.getElementById("safe-input");
  const blockInput = document.getElementById("block-input");
  const safeList = document.getElementById("safe-list");
  const blockList = document.getElementById("block-list");
  const safeEnabledEl = document.getElementById("safe-enabled");
  const blockEnabledEl = document.getElementById("block-enabled");
  const statusEl = document.getElementById("status");

  function normalizeDomain(input) {
    const trimmed = String(input).trim().toLowerCase();
    if (!trimmed) return "";
    try {
      let host = trimmed;
      if (host.includes("://")) {
        host = new URL(host).hostname;
      } else {
        host = host.split("/")[0].split(":")[0];
      }
      return host.replace(/^www\./i, "") || "";
    } catch {
      return "";
    }
  }

  function setStatus(message, isError) {
    statusEl.textContent = message || "";
    statusEl.classList.toggle("error", Boolean(isError));
    if (message && !isError) {
      window.clearTimeout(setStatus._t);
      setStatus._t = window.setTimeout(() => {
        statusEl.textContent = "";
      }, 2000);
    }
  }

  function loadLists() {
    return new Promise((resolve) => {
      chrome.storage.local.get(
        {
          [STORAGE_KEYS.safe]: [],
          [STORAGE_KEYS.blocked]: [],
          [STORAGE_KEYS.safeEnabled]: true,
          [STORAGE_KEYS.blockedEnabled]: true,
        },
        (data) => {
          if (chrome.runtime.lastError) {
            setStatus(chrome.runtime.lastError.message, true);
            resolve({
              safe: [],
              blocked: [],
              safeListEnabled: true,
              blockedListEnabled: true,
            });
            return;
          }
          resolve({
            safe: data[STORAGE_KEYS.safe] || [],
            blocked: data[STORAGE_KEYS.blocked] || [],
            safeListEnabled: data[STORAGE_KEYS.safeEnabled] !== false,
            blockedListEnabled: data[STORAGE_KEYS.blockedEnabled] !== false,
          });
        }
      );
    });
  }

  function saveLists(safe, blocked) {
    return new Promise((resolve) => {
      chrome.storage.local.set(
        {
          [STORAGE_KEYS.safe]: safe,
          [STORAGE_KEYS.blocked]: blocked,
        },
        () => {
          if (chrome.runtime.lastError) {
            setStatus(chrome.runtime.lastError.message, true);
          } else {
            setStatus("Saved.");
          }
          resolve();
        }
      );
    });
  }

  function renderList(ul, domains, type) {
    ul.innerHTML = "";
    if (!domains.length) {
      const p = document.createElement("li");
      p.className = "empty";
      p.textContent = "None yet.";
      ul.appendChild(p);
      return;
    }
    domains.forEach((domain, index) => {
      const li = document.createElement("li");
      const label = document.createElement("span");
      label.textContent = domain;
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "remove";
      btn.textContent = "Remove";
      btn.addEventListener("click", () => removeDomain(type, index));
      li.appendChild(label);
      li.appendChild(btn);
      ul.appendChild(li);
    });
  }

  let cachedSafe = [];
  let cachedBlocked = [];

  async function refreshUI() {
    const { safe, blocked, safeListEnabled, blockedListEnabled } = await loadLists();
    cachedSafe = [...safe];
    cachedBlocked = [...blocked];
    safeEnabledEl.checked = safeListEnabled;
    blockEnabledEl.checked = blockedListEnabled;
    renderList(safeList, cachedSafe, "safe");
    renderList(blockList, cachedBlocked, "blocked");
  }

  async function persistListEnabled(key, enabled) {
    return new Promise((resolve) => {
      chrome.storage.local.set({ [key]: enabled }, () => {
        if (chrome.runtime.lastError) {
          setStatus(chrome.runtime.lastError.message, true);
        } else {
          setStatus("Saved.");
        }
        resolve();
      });
    });
  }

  async function addDomain(type) {
    const input = type === "safe" ? safeInput : blockInput;
    const domain = normalizeDomain(input.value);
    if (!domain) {
      setStatus("Enter a valid domain.", true);
      return;
    }
    const list = type === "safe" ? cachedSafe : cachedBlocked;
    const other = type === "safe" ? cachedBlocked : cachedSafe;
    if (list.includes(domain)) {
      setStatus("Already in this list.", true);
      return;
    }
    if (other.includes(domain)) {
      setStatus("Remove it from the other list first.", true);
      return;
    }
    list.push(domain);
    list.sort();
    input.value = "";
    await saveLists(cachedSafe, cachedBlocked);
    await refreshUI();
  }

  async function removeDomain(type, index) {
    const list = type === "safe" ? cachedSafe : cachedBlocked;
    if (index < 0 || index >= list.length) return;
    list.splice(index, 1);
    await saveLists(cachedSafe, cachedBlocked);
    await refreshUI();
  }

  document.getElementById("safe-add").addEventListener("click", () => addDomain("safe"));
  document.getElementById("block-add").addEventListener("click", () => addDomain("blocked"));

  safeInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") addDomain("safe");
  });
  blockInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") addDomain("blocked");
  });

  safeEnabledEl.addEventListener("change", () => {
    persistListEnabled(STORAGE_KEYS.safeEnabled, safeEnabledEl.checked);
  });
  blockEnabledEl.addEventListener("change", () => {
    persistListEnabled(STORAGE_KEYS.blockedEnabled, blockEnabledEl.checked);
  });

  refreshUI();
})();
