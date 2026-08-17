"use strict";

(() => {
  const formatter = new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short",
  });

  document.querySelectorAll("[data-local-datetime]").forEach((element) => {
    const date = new Date(element.getAttribute("datetime") || "");

    if (!Number.isNaN(date.getTime())) {
      element.textContent = formatter.format(date);
    }
  });
})();
