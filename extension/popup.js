// Popup: the code for the current site (waiting for it if it hasn't arrived yet) and the other recent codes.
const $ = (id) => document.getElementById(id);
const h = (tag, props = {}, ...kids) => {
  const el = Object.assign(document.createElement(tag), props);
  for (const k of kids) el.append(k);
  return el;
};
let tab, host;
const ctrl = new AbortController();
window.addEventListener("unload", () => ctrl.abort());

function setMain(...nodes) { $("main").replaceChildren(...nodes); }

function warning(item) {
  if (item.match) return null;
  if (item.verified === false) return t("warnUnverified", item.sender_domain);
  return host ? t("warnOtherSite", item.sender_domain, host) : null;
}

function fillButton(item) {
  const fill = h("button", { className: item.match ? "primary" : "", textContent: item.match ? t("fill") : t("fillAnyway") });
  let armed = item.match;
  fill.onclick = async () => {
    if (!armed) {   // code from another sender: ask for an explicit second click (phishing protection)
      armed = true;
      fill.textContent = t("confirmFrom", item.sender_domain);
      fill.className = "primary";
      return;
    }
    fill.disabled = true;
    const ok = await fillInTab(tab.id, item, host).catch(() => false);
    if (ok) window.close();
    else fill.textContent = t("noField");
  };
  return fill;
}

function codeCard(item) {
  const card = h("div", { className: "card" });
  const from = h("div", { className: "meta", textContent: `${item.sender_domain} · ${ageText(item.age)}` });
  const subject = h("div", { className: "meta", textContent: item.subject });
  const row = h("div", { className: "row" });
  if (item.code) {
    card.append(h("div", { className: "code", textContent: item.code }));
    const copy = h("button", { className: host ? "" : "primary", textContent: t("copy") });
    copy.onclick = async () => { await navigator.clipboard.writeText(item.code); copy.textContent = t("copied"); };
    if (host) row.append(fillButton(item), copy);
    else row.append(copy);              // special tab (new tab, about: pages): nothing to fill
  } else if (item.link) {
    let linkHost = "";
    try { linkHost = new URL(item.link).protocol === "https:" ? new URL(item.link).hostname : ""; } catch { /* invalid */ }
    if (linkHost) {
      card.append(h("div", { className: "meta", textContent: t("signInLinkTo", linkHost) }));
      const open = h("button", { className: item.match ? "primary" : "", textContent: t("openLink") });
      let armed = item.match;
      open.onclick = async () => {
        if (!armed) {   // link from another sender: explicit second click, like codes
          armed = true;
          open.textContent = t("confirmFrom", item.sender_domain);
          open.className = "primary";
          return;
        }
        await browser.tabs.create({ url: item.link });
        window.close();
      };
      row.append(open);
    }
  }
  card.append(from, subject);
  const warn = warning(item);
  if (warn) card.append(h("div", { className: "warn", textContent: warn }));
  card.append(row);
  return card;
}

async function others() {
  const r = await api("/v1/recent", { domain: host }, ctrl.signal);
  if (r.status !== 200) return;
  const items = r.data.items.filter((x) => !x.match);
  if (!items.length) return $("others").replaceChildren();
  $("others").replaceChildren(h("h2", { textContent: t("otherRecent") }), ...items.map(codeCard));
}

async function waitForCode() {
  for (let i = 0; i < 4; i++) {          // up to ~3 minutes while the popup stays open
    setMain(h("div", { className: "card" }, h("span", { className: "spin" }), t("waitingFor", host),
      h("div", { className: "meta", textContent: t("waitingHelp") })));
    const r = await api("/v1/code", { domain: host, wait: 45 }, ctrl.signal);
    if (r.status === 200) { setMain(codeCard(r.data)); return others(); }
    if (r.status !== 204) return showError(r.status);
    others();
  }
  setMain(h("div", { className: "card meta", textContent: t("nothingReceived") }));
}

function showError(status) {
  if (status === -1 || status === 401) {
    const b = h("button", { className: "primary", textContent: t("openSettings") });
    b.onclick = () => { browser.runtime.openOptionsPage(); window.close(); };
    return setMain(h("div", { className: "card" }, status === -1 ? t("notConfigured") : t("keyRefused"), h("div", { className: "row" }, b)));
  }
  setMain(h("div", { className: "card err", textContent: status === 0 ? t("unreachable") : t("serverError", status) }));
}

(async () => {
  [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  host = tab ? siteOf(tab.url) : "";
  $("site").textContent = host || t("noSite");
  const { server, token } = await getSettings();
  if (!server || !token) return showError(-1);
  if (!(await hasPermission(server))) {
    const b = h("button", { className: "primary", textContent: t("allowServer", new URL(server).hostname) });
    b.onclick = async () => { if (await browser.permissions.request({ origins: [server + "/*"] })) location.reload(); };
    return setMain(h("div", { className: "card" }, t("needServerAccess"), h("div", { className: "row" }, b)));
  }
  if (!host) {
    const r = await api("/v1/recent", {}, ctrl.signal);
    if (r.status !== 200) return showError(r.status);
    return setMain(...(r.data.items.length ? r.data.items.map(codeCard) : [h("div", { className: "card meta", textContent: t("noRecent") })]));
  }
  try {
    const r = await api("/v1/code", { domain: host, wait: 0 }, ctrl.signal);
    if (r.status === 200) { setMain(codeCard(r.data)); others(); }
    else if (r.status === 204) waitForCode();
    else showError(r.status);
  } catch (e) { /* popup closed */ }
})();
