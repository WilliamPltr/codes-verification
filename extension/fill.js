// Injected into the page, so it must stay self-contained (no outside variables).
// Fills a code field and never submits the form. mode "focus": only if this frame has the focus.
// allowed: hostnames this frame may have (the tab's site, plus the sender's own subdomains for a matching code),
// so that a third-party frame on the page (an ad, a widget) never receives the code.
function codesFill(code, mode, allowed) {
  const here = location.protocol === "https:" ? location.hostname : "";
  if (!here || !allowed.some((h) => here === h || (h.startsWith(".") && here.endsWith(h)))) return { filled: false };
  if (mode === "focus" && !document.hasFocus()) return { filled: false };
  const BAD = /promo|coupon|postal|zip|gift|cadeau|discount|r[ée]duction|captcha|search|recherche|card|carte|cvc|cvv|iban|phone|t[ée]l[ée]phone|email|mail|user|login|name|nom/i;
  const GOOD = /otp|one.?time|code|token|verif|v[ée]rif|pin|2fa|mfa|totp|passcode|security|s[ée]curit|confirm/i;
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none" && !el.disabled && !el.readOnly;
  };
  const textual = (el) => {
    const type = (el.getAttribute("type") || "text").toLowerCase();
    if (type === "password") return (el.getAttribute("autocomplete") || "").includes("one-time-code");
    return ["text", "tel", "number", "search", ""].includes(type);
  };
  const hint = (el) => [el.name, el.id, el.placeholder, el.getAttribute("aria-label"), el.getAttribute("autocomplete"),
    el.getAttribute("data-testid"), el.labels && [...el.labels].map((l) => l.textContent).join(" ")].filter(Boolean).join(" ");
  const setValue = (el, v) => {
    el.focus();
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    setter.call(el, v);
    el.dispatchEvent(new InputEvent("input", { bubbles: true, data: v, inputType: "insertText" }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const inputs = [...document.querySelectorAll("input")].filter((el) => textual(el) && visible(el));


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
  // 1. separate boxes (one per character)
  const boxes = findBoxes(inputs);
  if (boxes && boxes.length === code.length) {
    boxes.forEach((el, i) => setValue(el, code[i]));
    boxes[boxes.length - 1].focus();
    return { filled: true, how: "cases" };
  }
  // 2. the focused input, if it looks like a code field (or nothing says otherwise)
  const a = document.activeElement;
  if (a && a.tagName === "INPUT" && textual(a) && visible(a) && !BAD.test(hint(a))) {
    setValue(a, code);
    return { filled: true, how: "focus" };
  }
  // 3. autocomplete="one-time-code"
  let el = inputs.find((i) => (i.getAttribute("autocomplete") || "").includes("one-time-code"));
  // 4. hints in the name, id or label
  el = el || inputs.find((i) => GOOD.test(hint(i)) && !BAD.test(hint(i)));
  // 5. the only short input on the page
  if (!el) {
    const short = inputs.filter((i) => !BAD.test(hint(i)) && (i.maxLength === -1 || (i.maxLength >= 4 && i.maxLength <= 12)));
    if (short.length === 1) el = short[0];
  }
  if (el) {
    setValue(el, code);
    return { filled: true, how: "champ" };
  }
  return { filled: false };
}

// Called from the background script or the popup: the focused frame first, then any frame of the same site.
// host: the site the code was requested for. If the tab has moved to another site meanwhile, nothing is filled.
async function fillInTab(tabId, item, host) {
  const tab = await browser.tabs.get(tabId);
  if (!host || siteOf(tab.url) !== host) return false;
  const allowed = [host];
  if (item.match && item.sender_domain) allowed.push(item.sender_domain, "." + item.sender_domain);
  for (const mode of ["focus", "any"]) {
    const res = await browser.scripting.executeScript({ target: { tabId, allFrames: true }, func: codesFill, args: [item.code, mode, allowed] });
    if (res.some((r) => r.result && r.result.filled)) return true;
  }
  return false;
}
