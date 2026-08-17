"use strict";

(() => {
  const format = document.getElementById("export-format");
  const filename = document.querySelector('[name="output_filename"]');
  if (!format || !filename) return;
  format.addEventListener("change", () => {
    const stem = filename.value.replace(/\.(parquet|jsonl)$/i, "") || "final";
    filename.value = `${stem}.${format.value}`;
  });
})();
