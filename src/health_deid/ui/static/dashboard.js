"use strict";

(() => {
  const summary = document.getElementById("live-summary");

  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = document.getElementById(button.dataset.copyTarget);
      if (!target) return;
      await navigator.clipboard.writeText(target.textContent || "");
      const original = button.textContent;
      button.textContent = "Copied";
      window.setTimeout(() => {
        button.textContent = original;
      }, 1200);
    });
  });
  const reportDownload = document.getElementById("download-report-json");
  reportDownload?.addEventListener("click", () => {
    const text =
      document.getElementById("live-report-json")?.textContent || "{}";
    const link = document.createElement("a");
    link.href = URL.createObjectURL(
      new Blob([text], { type: "application/json" }),
    );
    link.download =
      reportDownload.dataset.filename || "health-deid-report.json";
    link.click();
    URL.revokeObjectURL(link.href);
  });

  if (!summary) return;
  const update = (id, value) => {
    const node = document.getElementById(id);
    if (node) node.textContent = String(value ?? "—").replaceAll("_", " ");
  };
  const poll = async () => {
    try {
      const response = await fetch(summary.dataset.statusUrl, {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) return;
      const payload = await response.json();
      const report = payload.report;
      update("run-status", report.run.status);
      update("record-total", report.records.denominator);
      update("review-count", report.review.pending);
      update("exportable-count", report.records.exportable);
      const raw = document.getElementById("live-report-json");
      if (raw) raw.textContent = JSON.stringify(report, null, 2);
      const changed =
        report.run.status !== summary.dataset.runStatus ||
        payload.job.state !== summary.dataset.jobState;
      if (changed) window.location.reload();
    } catch (_) {
      // The next poll retries; the durable status remains available in SQLite.
    }
  };
  window.setInterval(poll, 2500);
})();
