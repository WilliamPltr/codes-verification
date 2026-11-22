const $ = (id) => document.getElementById(id);
const ALL = "https://*/*";
localize();

async function showPermAll() {
  const { auto } = await browser.storage.local.get("auto");
  $("auto").checked = auto !== false;
  if (auto === false || (await browser.permissions.contains({ origins: [ALL] }))) return $("permall").replaceChildren();
  const b = document.createElement("button");
  b.className = "primary";
  b.textContent = t("allowAllSites");
  b.onclick = async () => { await browser.permissions.request({ origins: [ALL] }); showPermAll(); };
  $("permall").replaceChildren(b);
}

$("auto").onchange = async () => { await browser.storage.local.set({ auto: $("auto").checked }); showPermAll(); };

function status(cls, text) {
  $("status").className = cls;
  $("status").textContent = text;
}

async function test() {
  const { server, token } = await getSettings();
  if (!server) return status("meta", t("noServer"));
  if (!(await hasPermission(server))) return status("err", t("needPermission", new URL(server).hostname));
  if (!token) return status("meta", t("noKey"));
  const r = await api("/v1/me");
  if (r.status === 200) status("ok", t("connected", r.data.device));
  else if (r.status === 401) status("err", t("keyRefused"));
  else status("err", r.status === 0 ? t("unreachable") : t("serverError", r.status));
}

$("save").onclick = () => {
  const server = normalizeServer($("server").value);
  if (!server) return status("err", t("badServer"));
  // permissions.request() has to run right away inside the click handler, before any await
  const asked = browser.permissions.request({ origins: [server + "/*"] }).catch(() => false);
  (async () => {
    await asked;
    const token = $("token").value.trim();
    await browser.storage.local.set(token ? { server, token } : { server });
    $("server").value = server;
    if (token) {
      $("token").value = "";
      $("token").placeholder = t("keySaved");
    }
    test();
  })();
};

(async () => {
  const { server, token } = await getSettings();
  $("server").value = server;
  if (token) $("token").placeholder = t("keySaved");
  showPermAll();
  test();
})();
