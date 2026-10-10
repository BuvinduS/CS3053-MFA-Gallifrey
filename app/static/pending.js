(function () {
  var POLL_MS = 2000;
  var messageEl = document.getElementById("status-message");

  var MESSAGES = {
    PENDING: "Waiting for approval on your phone...",
    APPROVED: "Approved. Signing you in...",
    DENIED: "The request was denied on your phone.",
    EXPIRED: "This login attempt has expired. Please log in again.",
    LOCKED: "This account is temporarily locked.",
    UNAVAILABLE: "The second-step service is unavailable. Still trying...",
    ERROR: "Something went wrong with the second step. Please log in again.",
  };
  // Stop polling on these; UNAVAILABLE is treated as temporary and keeps polling.
  var TERMINAL = { DENIED: 1, EXPIRED: 1, LOCKED: 1, ERROR: 1 };

  // The server already rendered the PENDING text, so don't announce it again.
  var lastStatus = "PENDING";

  function show(status) {
    // Update (and therefore announce) only when the status actually changes.
    if (status === lastStatus) return;
    lastStatus = status;
    messageEl.textContent = MESSAGES[status] || MESSAGES.ERROR;
  }

  function handle(status) {
    show(status);
    if (status === "APPROVED") {
      complete();
      return;
    }
    if (TERMINAL[status]) return;
    setTimeout(poll, POLL_MS);
  }

  async function poll() {
    try {
      var res = await fetch("/auth/status", { credentials: "same-origin" });
      var data = await res.json();
      handle(data.status);
    } catch (e) {
      handle("UNAVAILABLE");
    }
  }

  async function complete() {
    try {
      var res = await fetch("/auth/complete", {
        method: "POST",
        credentials: "same-origin",
      });
      var data = await res.json();
      if (res.ok && data.redirect) {
        window.location.assign(data.redirect);
        return;
      }
      handle(data.status || "ERROR");
    } catch (e) {
      handle("UNAVAILABLE");
    }
  }

  setTimeout(poll, POLL_MS);
})();
