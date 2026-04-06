// Phish Catcher — Levenshtein typosquat check vs target roots; safe/blocked lists from storage.
(function () {
  "use strict";

  const TARGET_ROOT_DOMAINS = ["paypal.com", "google.com", "bankofamerica.com"];
  const MARK_ATTR = "data-phish-catcher-flagged";
  const BADGE_ATTR = "data-phish-catcher-badge";
  const SAFE_MARK_ATTR = "data-phish-catcher-safe";
  const SAFE_BADGE_ATTR = "data-phish-catcher-safe-badge";
  const STORAGE = {
    safe: "safeDomains",
    blocked: "blockedDomains",
    safeEnabled: "safeListEnabled",
    blockedEnabled: "blockedListEnabled",
  };

  /**
   * Levenshtein distance: minimum edits (insert/delete/substitute) to turn a into b.
   */
  function levenshtein(a, b) {
    const m = a.length;
    const n = b.length;
    if (m === 0) return n;
    if (n === 0) return m;
    const row = new Array(n + 1);
    for (let j = 0; j <= n; j++) row[j] = j;
    for (let i = 1; i <= m; i++) {
      let prev = row[0];
      row[0] = i;
      for (let j = 1; j <= n; j++) {
        const tmp = row[j];
        const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
        row[j] = Math.min(row[j] + 1, row[j - 1] + 1, prev + cost);
        prev = tmp;
      }
    }
    return row[n];
  }

  /**
   * Approximate DNS "root" for our .com targets: last two labels (e.g. accounts.google.com → google.com).
   * Leading www. should already be stripped on the hostname passed in.
   */
  function getRootDomain(hostname) {
    const h = hostname.toLowerCase().replace(/\.$/, "");
    const parts = h.split(".").filter(Boolean);
    if (parts.length < 2) return h;
    return parts.slice(-2).join(".");
  }

  function isTyposquatRootAgainstTargets(root) {
    const r = root.toLowerCase();
    if (!r) return false;
    for (let i = 0; i < TARGET_ROOT_DOMAINS.length; i++) {
      const t = TARGET_ROOT_DOMAINS[i];
      const d = levenshtein(r, t);
      if (d === 1 || d === 2) return true;
    }
    return false;
  }

  /** Exact match to a trusted brand root (e.g. google.com, not a typosquat). */
  function isLegitimateTargetRoot(root) {
    const r = root.toLowerCase();
    return TARGET_ROOT_DOMAINS.some((t) => t === r);
  }

  function hostMatchesListedDomain(hostname, domains) {
    const h = hostname.toLowerCase();
    return domains.some((entry) => {
      const t = String(entry).toLowerCase();
      return h === t || (h.length > t.length && h.endsWith("." + t));
    });
  }

  function loadUserLists() {
    return new Promise((resolve) => {
      chrome.storage.local.get(
        {
          [STORAGE.safe]: [],
          [STORAGE.blocked]: [],
          [STORAGE.safeEnabled]: true,
          [STORAGE.blockedEnabled]: true,
        },
        (r) => {
          resolve({
            safe: r[STORAGE.safe] || [],
            blocked: r[STORAGE.blocked] || [],
            safeListEnabled: r[STORAGE.safeEnabled] !== false,
            blockedListEnabled: r[STORAGE.blockedEnabled] !== false,
          });
        }
      );
    });
  }

  /**
   * Parse href → http(s) hostname only (no path, query, or hash). Strip leading www.
   */
  function getLinkHostname(anchor) {
    const raw = anchor.getAttribute("href");
    if (!raw || /^\s*(javascript:|mailto:|tel:|#)/i.test(raw)) return null;
    try {
      const url = new URL(raw, document.baseURI);
      if (url.protocol !== "http:" && url.protocol !== "https:") return null;
      const host = url.hostname.toLowerCase().replace(/^www\./i, "") || null;
      if (!host) return null;
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) return null;
      return host;
    } catch {
      return null;
    }
  }

  function unmarkSuspiciousLink(anchor) {
    if (anchor.getAttribute(MARK_ATTR) !== "1") return;
    anchor.removeAttribute(MARK_ATTR);
    anchor.style.border = "";
    anchor.style.boxSizing = "";
    const next = anchor.nextElementSibling;
    if (next && next.getAttribute(BADGE_ATTR) === "1") next.remove();
  }

  function unmarkSafeLink(anchor) {
    if (anchor.getAttribute(SAFE_MARK_ATTR) !== "1") return;
    anchor.removeAttribute(SAFE_MARK_ATTR);
    const next = anchor.nextElementSibling;
    if (next && next.getAttribute(SAFE_BADGE_ATTR) === "1") next.remove();
  }

  function markSuspiciousLink(anchor) {
    if (anchor.getAttribute(MARK_ATTR) === "1") return;
    anchor.setAttribute(MARK_ATTR, "1");

    const badge = document.createElement("span");
    badge.setAttribute(BADGE_ATTR, "1");
    badge.setAttribute("aria-label", "Suspicious link");
    badge.style.display = "inline-flex";
    badge.style.alignItems = "center";
    badge.style.justifyContent = "center";
    badge.style.marginLeft = "4px";
    badge.style.verticalAlign = "middle";
    badge.style.lineHeight = "0";
    badge.style.width = "16px";
    badge.style.height = "16px";
    badge.style.borderRadius = "5px";
    badge.style.flexShrink = "0";
    badge.style.userSelect = "none";
    badge.style.background = "linear-gradient(to bottom, #fb7185, #dc2626 52%, #991b1b)";
    badge.innerHTML =
      '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" aria-hidden="true">' +
      '<path fill="none" stroke="#fff" stroke-width="2.75" stroke-linecap="round" d="M7.5 7.5l9 9M16.5 7.5l-9 9"/>' +
      "</svg>";

    anchor.insertAdjacentElement("afterend", badge);
  }

  function markSafeLink(anchor) {
    if (anchor.getAttribute(SAFE_MARK_ATTR) === "1") return;
    anchor.setAttribute(SAFE_MARK_ATTR, "1");

    const badge = document.createElement("span");
    badge.setAttribute(SAFE_BADGE_ATTR, "1");
    badge.setAttribute("aria-label", "Safe domain");
    badge.style.display = "inline-flex";
    badge.style.alignItems = "center";
    badge.style.marginLeft = "4px";
    badge.style.verticalAlign = "middle";
    badge.style.lineHeight = "0";
    badge.innerHTML =
      '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" aria-hidden="true">' +
      '<circle cx="12" cy="12" r="12" fill="#16a34a"/>' +
      '<path fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" d="M7 12l3 3 7-7"/>' +
      "</svg>";

    anchor.insertAdjacentElement("afterend", badge);
  }

  function clearAllMarks() {
    document.querySelectorAll(`a[${MARK_ATTR}="1"]`).forEach(unmarkSuspiciousLink);
    document.querySelectorAll(`a[${SAFE_MARK_ATTR}="1"]`).forEach(unmarkSafeLink);
  }

  function isPhishCatcherTestPage() {
    const p = location.pathname || "";
    return /(^|\/)test-page\.html$/i.test(p);
  }

  function hostForHrefFromStoredDomain(domain) {
    const s = String(domain).trim().toLowerCase();
    if (!s) return "";
    try {
      if (s.includes("://")) return new URL(s).hostname.replace(/^www\./i, "") || "";
    } catch {
      /* fall through */
    }
    return s.replace(/^www\./i, "").split("/")[0].split(":")[0] || "";
  }

  function renderTestPageDemoLists(safe, blocked) {
    const blockedUl = document.getElementById("phish-catcher-demo-blocked");
    const safeUl = document.getElementById("phish-catcher-demo-safe");
    if (!blockedUl || !safeUl) return;

    function fillUl(ul, domains, emptyMessage) {
      ul.innerHTML = "";
      if (!domains.length) {
        const li = document.createElement("li");
        li.className = "phish-catcher-demo-empty";
        li.textContent = emptyMessage;
        ul.appendChild(li);
        return;
      }
      [...domains].sort().forEach((entry) => {
        const host = hostForHrefFromStoredDomain(entry);
        if (!host) return;
        const li = document.createElement("li");
        const a = document.createElement("a");
        a.href = "https://" + host + "/";
        a.textContent = host;
        li.appendChild(a);
        ul.appendChild(li);
      });
    }

    fillUl(
      blockedUl,
      blocked,
      "No blocked domains yet — add some in the extension popup."
    );
    fillUl(safeUl, safe, "No safe domains yet — add some in the extension popup.");
  }

  function scanAnchorsWithLists(safe, blocked, safeListEnabled, blockedListEnabled) {
    document.querySelectorAll("a[href]").forEach((a) => {
      const host = getLinkHostname(a);
      if (!host) return;
      const root = getRootDomain(host);

      if (blockedListEnabled && hostMatchesListedDomain(host, blocked)) {
        markSuspiciousLink(a);
        return;
      }

      if (
        safeListEnabled &&
        (hostMatchesListedDomain(host, safe) || isLegitimateTargetRoot(root))
      ) {
        markSafeLink(a);
        return;
      }

      if (blockedListEnabled && isTyposquatRootAgainstTargets(root)) markSuspiciousLink(a);
    });
  }

  async function runScan() {
    clearAllMarks();
    const lists = await loadUserLists();
    if (isPhishCatcherTestPage()) renderTestPageDemoLists(lists.safe, lists.blocked);
    scanAnchorsWithLists(
      lists.safe,
      lists.blocked,
      lists.safeListEnabled,
      lists.blockedListEnabled
    );
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", runScan);
  } else {
    runScan();
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    if (
      changes[STORAGE.safe] ||
      changes[STORAGE.blocked] ||
      changes[STORAGE.safeEnabled] ||
      changes[STORAGE.blockedEnabled]
    ) {
      runScan();
    }
  });
})();
