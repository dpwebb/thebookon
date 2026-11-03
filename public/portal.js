(async function () {
  function text(value) {
    return value == null ? "" : String(value);
  }

  function escapeHtml(value) {
    return text(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
  }

  function formatDate(value) {
    if (!value) return "";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleDateString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric"
    });
  }

  async function getSession() {
    const response = await fetch("/api/session", {
      credentials: "same-origin",
      headers: { "Accept": "application/json" }
    });
    return response.json();
  }

  function fillSubmissionForm(session) {
    const form = document.querySelector("[data-submission-form]");
    if (!form) return;

    const notice = document.querySelector("[data-submission-session]");
    if (session.authenticated) {
      form.elements.author_name.value = form.elements.author_name.value || text(session.user.fullName);
      form.elements.email.value = form.elements.email.value || text(session.user.email);
      form.elements.phone.value = form.elements.phone.value || text(session.user.phone);
      if (notice) {
        notice.innerHTML = `Signed in as <strong>${escapeHtml(session.user.fullName)}</strong>. This submission will be attached to your dashboard.`;
        notice.hidden = false;
      }
    } else if (notice) {
      notice.innerHTML = `You can submit as a guest, or <a href="/login/">log in</a> first so the manuscript is attached to your dashboard.`;
      notice.hidden = false;
    }
  }

  function renderDashboard(session) {
    const target = document.querySelector("[data-dashboard]");
    if (!target) return;

    if (!session.authenticated) {
      target.innerHTML = `
        <div class="notice">
          <p>Please log in or create an author account to view manuscript status.</p>
          <p><a class="button" href="/login/">Log in</a> <a class="button secondary" href="/register/">Create account</a></p>
        </div>
      `;
      return;
    }

    const rows = session.submissions.map((submission) => `
      <article class="dashboard-card">
        <div>
          <p class="eyebrow">${escapeHtml(submission.category) || "Manuscript"}</p>
          <h2>${escapeHtml(submission.title)}</h2>
          <p><strong>Reference:</strong> ${escapeHtml(submission.id)}</p>
          ${submission.withdrawalState === "confirmed"
            ? "<p>Editorial confirmed that your manuscript was withdrawn.</p>"
            : submission.withdrawalState === "requested"
              ? "<p>Withdrawal requested. Editorial review is pending.</p>"
              : `<form action="/api/manuscripts/withdrawal" method="post">
                   <input type="hidden" name="id" value="${escapeHtml(submission.id)}">
                   <button class="button secondary" type="submit">Request withdrawal</button>
                 </form>`}
          <p><strong>File:</strong> ${escapeHtml(submission.fileName) || "Recorded"}</p>
        </div>
        <dl class="status-grid">
          <div><dt>Status</dt><dd>${escapeHtml(submission.status)}</dd></div>
          <div><dt>Review</dt><dd>${escapeHtml(submission.reviewState)}</dd></div>
          <div><dt>Submitted</dt><dd>${escapeHtml(formatDate(submission.createdAt))}</dd></div>
          <div><dt>Path</dt><dd>${escapeHtml(submission.serviceInterest)}</dd></div>
        </dl>
      </article>
    `).join("");

    target.innerHTML = `
      <div class="notice">
        <p>Signed in as <strong>${escapeHtml(session.user.fullName)}</strong> (${escapeHtml(session.user.email)}).</p>
        <form action="/api/logout" method="post"><button class="button secondary" type="submit">Log out</button></form>
      </div>
      ${rows || `
        <div class="notice">
          <p>No submissions are attached to this account yet.</p>
          <p><a class="button" href="/manuscript-submission/">Submit a manuscript</a></p>
        </div>
      `}
    `;
  }

  const reference = new URLSearchParams(window.location.search).get("withdraw");
  const contactForm = document.querySelector('form[action="/api/contact"]');
  if (contactForm && /^ms_[a-z0-9]+_[a-f0-9]{10}$/.test(reference || "")) {
    contactForm.elements.topic.value = "Manuscript withdrawal";
    if (!contactForm.elements.message.value) {
      contactForm.elements.message.value = "Please withdraw my manuscript submission " + reference + " and confirm the outcome.";
    }
  }
  if (!document.querySelector("[data-dashboard], [data-submission-form]")) return;

  try {
    const session = await getSession();
    fillSubmissionForm(session);
    renderDashboard(session);
  } catch (error) {
    const target = document.querySelector("[data-dashboard]");
    if (target) {
      target.innerHTML = `<div class="notice"><p>The dashboard could not load. Please refresh or contact support.</p></div>`;
    }
  }
}());
