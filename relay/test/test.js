// "Send me a code": asks the server for a test code. Depending on the server settings this is a real email
// (always sent to the owner's address, rate limited) or a simulated code that skips Gmail.
const MODES = {
  email: "The button sends a real email to the owner of this server, which tests the whole chain including Gmail.",
  simulated: "No email is involved: the server makes up a code, which tests the extension, the relay and the service.",
  off: "The button is disabled on this server. Try the extension on any site that emails you a code.",
};

fetch("/v1/health", { cache: "no-store" }).then((r) => r.json()).then((h) => {
  const mode = document.getElementById("mode");
  if (mode) mode.textContent = MODES[h.test] || "";
  const send = document.getElementById("send");
  if (send && h.test === "off") send.disabled = true;
}).catch(() => {});

const sendButton = document.getElementById("send");
if (sendButton) sendButton.onclick = async () => {
  const state = document.getElementById("state");
  sendButton.disabled = true;
  state.textContent = "Sending…";
  try {
    const r = await fetch("/test/send", { method: "POST" });
    const d = await r.json().catch(() => ({}));
    if (r.ok) state.textContent = d.mode === "simulated" ? "Code created. Don't touch anything, it should show up in a second." : "Email sent. Don't touch anything, the code should show up within a few seconds.";
    else state.textContent = d.error || `Error ${r.status}`;
  } catch {
    state.textContent = "Server unreachable.";
  }
  setTimeout(() => { sendButton.disabled = false; }, 15000);
};

function verify(code) {
  document.getElementById("result").textContent = code ? `Form submitted with code ${code}` : "";
}
