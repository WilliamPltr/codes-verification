// Shared by the background script, the popup and the settings page.
const t = (key, ...subs) => browser.i18n.getMessage(key, subs.map(String)) || key;

function localize(root = document) {
  for (const el of root.querySelectorAll("[data-i18n]")) el.textContent = t(el.dataset.i18n);
  for (const el of root.querySelectorAll("[data-i18n-placeholder]")) el.placeholder = t(el.dataset.i18nPlaceholder);
}

// "https://codes.example.com/anything" -> "https://codes.example.com", or "" when not a usable https address
function normalizeServer(value) {
  try {
    const u = new URL(String(value || "").trim());
    return u.protocol === "https:" && u.hostname ? u.origin : "";
  } catch {
    return "";
  }
}

async function getSettings() {
  const { token, server } = await browser.storage.local.get(["token", "server"]);
  return { token: token || "", server: normalizeServer(server) || normalizeServer(DEFAULT_SERVER) };
}

async function hasPermission(server) {
  server = server || (await getSettings()).server;
  return Boolean(server) && browser.permissions.contains({ origins: [server + "/*"] });
}

// -> { status, data }. status: 0 = network error or server unreachable, -1 = not configured
async function api(path, params = {}, signal) {
  const { token, server } = await getSettings();
  if (!token || !server) return { status: -1, data: null };
  const url = new URL(server + path);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, String(v));
  try {
    const r = await fetch(url, { headers: { Authorization: "Bearer " + token }, cache: "no-store", credentials: "omit", signal });
    const data = r.status === 200 ? await r.json() : null;
    return { status: r.status, data };
  } catch (e) {
    if (e.name === "AbortError") throw e;
    return { status: 0, data: null };
  }
}

// Codes only ever go to https pages: on plain http, anyone on the network could read or change the page.
function siteOf(url) {
  try {
    const u = new URL(url);
    return u.protocol === "https:" ? u.hostname : "";
  } catch {
    return "";
  }
}

function ageText(s) {
  return s < 60 ? t("secondsAgo", s) : t("minutesAgo", Math.floor(s / 60));
}
