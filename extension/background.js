// First install: open the settings so the user only has to paste the access key.
browser.runtime.onInstalled.addListener(async ({ reason }) => {
  if (reason !== "install") return;
  const { token, server } = await getSettings();
  if (!token || !server) browser.runtime.openOptionsPage();
});

// Auto mode: a page (detect.js) found a code field and asks whether the code has arrived (10 s long-poll per request).
// The domain comes from the frame's real address (sender.url), never from anything the page says.
browser.runtime.onMessage.addListener((msg, sender) => {
  if (!msg || msg.type !== "codes-wait") return;
  return (async () => {
    const { auto } = await browser.storage.local.get("auto");
    if (auto === false) return { status: -2 };
    const host = siteOf(sender.url || "");
    const top = siteOf((sender.tab && sender.tab.url) || "");
    if (!host || !top || !(await hasPermission())) return { status: -1 };
    const after = Number.isFinite(msg.after) ? msg.after : 0;
    // top: the code must also belong to the tab's site, so a page can't get a code auto-filled into
    // another site it embeds in an (invisible) frame
    const r = await api("/v1/code", { domain: host, top, wait: 10, after });
    if (r.status === 200 && r.data.code) badge("✓", "#16a34a");
    return { status: r.status, data: r.data };
  })();
});

// Keyboard shortcut (fallback): asks for the current site's code, waiting for it if needed, and fills it in.
let pending = null;

async function badge(text, color, ms = 4000) {
  await browser.action.setBadgeText({ text });
  if (color) await browser.action.setBadgeBackgroundColor({ color });
  if (ms) setTimeout(() => browser.action.setBadgeText({ text: "" }), ms);
}

browser.commands.onCommand.addListener(async (command) => {
  if (command !== "fill-code") return;
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  const host = tab && siteOf(tab.url);
  if (!host) return badge("×", "#6b7280");
  if (!(await getSettings()).token || !(await hasPermission())) {
    await badge("!", "#dc2626");
    return browser.runtime.openOptionsPage();
  }
  if (pending) pending.abort();
  pending = new AbortController();
  const signal = pending.signal;
  await badge("…", "#2563eb", 0);
  try {
    const started = Date.now();
    let r = { status: 204 };
    while (r.status === 204 && Date.now() - started < 90000) {      // waits up to 90 s (two long-polls)
      r = await api("/v1/code", { domain: host, wait: 45 }, signal);
    }
    if (r.status === 401) { await badge("!", "#dc2626"); return browser.runtime.openOptionsPage(); }
    if (r.status !== 200) return badge(r.status === 204 ? "–" : "×", "#6b7280");
    const item = r.data;
    if (item.code) {
      const ok = await fillInTab(tab.id, item, host);
      if (ok) return badge("✓", "#16a34a");
      await navigator.clipboard.writeText(item.code).catch(() => {});
      return badge("📋", "#2563eb");          // no field found: the code is in the clipboard
    }
    if (item.link) {
      await badge("↗", "#2563eb", 15000);
      return browser.action.openPopup().catch(() => {});   // the popup offers to open the link
    }
  } catch (e) {
    if (e.name !== "AbortError") badge("×", "#dc2626");
  } finally {
    if (pending && pending.signal === signal) pending = null;
  }
});
