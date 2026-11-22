// Auto mode: spots a verification code field on the page, waits for the code (through the background script)
// and fills it in as soon as it arrives. Never submits the form, never overwrites what the user typed.
(() => {
  if (window.__codesDetect || location.protocol !== "https:" || !location.hostname) return;
  window.__codesDetect = true;
  const t = (key, ...subs) => browser.i18n.getMessage(key, subs.map(String)) || key;

  const HINT = /one-time-code|otp|one.?time|verif|v[ée]rif|security.?code|code.?de.?s[ée]curit|2fa|mfa|totp|passcode|auth\w*.?code|sms.?code|e-?mail.?code|confirmation.?code|login.?code|code.?de.?connexion|sudo|\bpin\b|\bcode\b/i;
  const BAD = /promo|coupon|postal|zip|gift|cadeau|discount|r[ée]duction|captcha|search|recherche|card|carte|cvc|cvv|iban|phone|t[ée]l[ée]?phone|e-?mail(?!.?code)|user|username|identifiant|login(?!.?code)|name|nom|password|passe|address|adresse|city|ville|country|pays|coupon|voucher|referral|parrain/i;
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none" && !el.disabled && !el.readOnly;
  };
  const textual = (el) => {
    const type = (el.getAttribute("type") || "text").toLowerCase();
    if (type === "password") return (el.getAttribute("autocomplete") || "").includes("one-time-code");
    return ["text", "tel", "number", ""].includes(type);
  };
  const hint = (el) => [el.name, el.id, el.placeholder, el.getAttribute("aria-label"), el.getAttribute("autocomplete"),
    el.getAttribute("data-testid"), el.labels && [...el.labels].map((l) => l.textContent).join(" ")].filter(Boolean).join(" ");


  // separate boxes: maxlength=1 inputs, or a group of 4 to 8 narrow inputs in the same block (limit enforced by the site's script)
  const findBoxes = (inputs) => {
    const singles = inputs.filter((el) => el.maxLength === 1);
    if (singles.length >= 4 && singles.length <= 8) return singles;
    const groups = new Map();
    for (const el of inputs) {
      const w = el.getBoundingClientRect().width;
      if (w <= 0 || w > 80 || BAD.test(hint(el))) continue;
      let a = el.parentElement;
      for (let k = 0; k < 3 && a; k++, a = a.parentElement) {
        if (!groups.has(a)) groups.set(a, []);
        groups.get(a).push(el);
      }
    }
    let best = null;
    for (const els of groups.values()) {
      if (els.length >= 4 && els.length <= 8 && (!best || els.length > best.length)) best = els;
    }
    return best;
  };

  function findField() {
    const inputs = [...document.querySelectorAll("input")].filter((el) => textual(el) && visible(el));
    const boxes = findBoxes(inputs);
    if (boxes) return { kind: "cases", els: boxes };
    let el = inputs.find((i) => (i.getAttribute("autocomplete") || "").includes("one-time-code"));
    el = el || inputs.find((i) => HINT.test(hint(i)) && !BAD.test(hint(i)));
    return el ? { kind: "one", els: [el] } : null;
  }

  function setValue(el, v) {
    el.focus();
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(el, v);
    el.dispatchEvent(new InputEvent("input", { bubbles: true, data: v, inputType: "insertText" }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function write(field, code) {
    if (field.kind === "cases") {
      if (field.els.length !== code.length) return false;
      field.els.forEach((el, i) => setValue(el, code[i]));
    } else {
      setValue(field.els[0], code);
    }
    return true;
  }

  // ---- notification bubble (closed Shadow DOM: the page's styles don't leak in, ours don't leak out)
  let bubble;
  function toast(text, actions = [], ms = 9000) {
    if (bubble) bubble.remove();
    bubble = document.createElement("div");
    const root = bubble.attachShadow({ mode: "closed" });
    const st = document.createElement("style");
    st.textContent = `.b{position:fixed;right:16px;bottom:16px;z-index:2147483647;max-width:380px;background:#111827;color:#f9fafb;
      font:13px/1.4 system-ui,-apple-system,"Segoe UI",sans-serif;border-radius:10px;padding:10px 12px;box-shadow:0 6px 24px rgba(0,0,0,.3);
      display:flex;gap:10px;align-items:center}.t{flex:1}button{font:inherit;border:0;border-radius:6px;padding:4px 9px;cursor:pointer;
      background:#2563eb;color:#fff}button.s{background:#374151}`;
    const box = document.createElement("div");
    box.className = "b";
    const message = document.createElement("div");
    message.className = "t";
    message.textContent = text;
    box.append(message);
    for (const [label, fn, secondary] of actions) {
      const b = document.createElement("button");
      b.textContent = label;
      if (secondary) b.className = "s";
      b.onclick = () => { fn(); bubble.remove(); };
      box.append(b);
    }
    const close = document.createElement("button");
    close.className = "s";
    close.textContent = "×";
    close.title = t("close");
    close.onclick = () => bubble.remove();
    box.append(close);
    root.append(st, box);
    document.documentElement.append(bubble);
    if (ms) setTimeout(() => bubble && bubble.remove(), ms);
  }

  // ---- filling: a code written by the extension may be replaced by a newer one; something the user typed, never
  let lastFilled = "";
  const current = (field) => field.els.map((el) => el.value).join("").trim();

  function deliver(item, replacing) {
    const field = findField();
    const shown = t(replacing ? "newCodeFromIs" : "codeFromIs", item.sender_domain, item.code);
    const copy = [t("copy"), () => navigator.clipboard.writeText(item.code)];
    if (!field) return toast(shown, [copy]);
    const value = current(field);
    if (value !== "" && value !== lastFilled) {   // the user typed something: offer, don't overwrite
      return toast(shown, [[t("fill"), () => { field.els.forEach((el) => setValue(el, "")); write(field, item.code); lastFilled = item.code; }]], 20000);
    }
    if (value) field.els.forEach((el) => setValue(el, ""));
    if (write(field, item.code)) {
      lastFilled = item.code;
      toast(t(replacing ? "filledNewCode" : "filledCode", item.sender_domain), [[t("undo"), () => { field.els.forEach((el) => setValue(el, "")); lastFilled = ""; }, true]]);
    } else {
      toast(shown, [copy], 20000);
    }
  }

  // ---- listening: while the field is there, up to 15 min after the last action on the page; paused while the tab is hidden
  const WINDOW = 15 * 60000;
  let state = "idle", deadline = 0, after = 0, lastId = "";
  const bump = (e) => {                         // only real user actions extend the window, not page scripts
    if (!e.isTrusted) return;
    deadline = Date.now() + WINDOW;
    if (state === "idle") run();
  };
  const tabVisible = () => document.visibilityState === "visible" ? Promise.resolve() :
    new Promise((ok) => document.addEventListener("visibilitychange", function f() {
      if (document.visibilityState === "visible") { document.removeEventListener("visibilitychange", f); ok(); }
    }));

  async function run() {
    if (!deadline) deadline = Date.now() + WINDOW;                // initial window; only a user action extends it
    if (state !== "idle" || Date.now() >= deadline || !findField()) return;
    state = "waiting";
    if (!after) after = Math.floor(Date.now() / 1000) - 300;     // first round: accept codes received up to 5 min ago
    try {
      while (Date.now() < deadline && findField()) {
        await tabVisible();
        let r;
        try { r = await browser.runtime.sendMessage({ type: "codes-wait", after }); } catch { break; }
        if (!r || r.status === -1 || r.status === 401 || r.status === -2) break;   // not configured, or turned off
        if (r.status === 200 && r.data.code && r.data.match && r.data.id !== lastId) {
          deliver(r.data, lastId !== "");
          lastId = r.data.id;
          after = r.data.received + 1;            // from now on: only a newer code
          deadline = Date.now() + WINDOW;
        } else if (r.status !== 204) {
          await new Promise((ok) => setTimeout(ok, 5000));
        }
      }
    } finally {
      state = "idle";                             // the next action on the page starts listening again
    }
  }

  addEventListener("click", bump, true);
  addEventListener("keydown", bump, true);

  let timer;
  const obs = new MutationObserver(() => { clearTimeout(timer); timer = setTimeout(run, 400); });
  run();
  obs.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["type", "autocomplete", "style", "class", "hidden"] });
})();
