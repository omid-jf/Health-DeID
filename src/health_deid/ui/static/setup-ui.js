"use strict";

(() => {
  const form = document.getElementById("setup-form");
  if (!form) return;

  const panels = [...form.querySelectorAll("[data-step]")];
  const tabs = [...document.querySelectorAll("[data-step-target]")];
  const showStep = (name, scroll = true) => {
    if (!panels.some((panel) => panel.dataset.step === name)) return;
    panels.forEach((panel) => { panel.hidden = panel.dataset.step !== name; });
    tabs.forEach((tab) => {
      tab.classList.toggle("active", tab.dataset.stepTarget === name);
      tab.setAttribute("aria-current", tab.dataset.stepTarget === name ? "step" : "false");
    });
    if (scroll) window.scrollTo({ top: 0, behavior: "smooth" });
  };
  document.addEventListener("click", (event) => {
    if (!(event.target instanceof Element)) return;
    const trigger = event.target.closest("[data-step-target], [data-next], [data-back]");
    const target = trigger?.dataset.stepTarget ?? trigger?.dataset.next ?? trigger?.dataset.back;
    if (target) showStep(target);
  });
  showStep(form.dataset.initialStep || "data", false);

  const syncColumns = () => {
    const roleColumns = new Set(
      ["record_id_column", "entity_id_column", "text_column"]
        .map((name) => form.querySelector(`input[name="${name}"]:checked`)?.value)
        .filter(Boolean),
    );
    form.querySelectorAll("[data-column-row]").forEach((row) => {
      const metadata = row.querySelector("[data-metadata-toggle]");
      const structured = row.querySelector("[data-structured-toggle]");
      const category = row.querySelector("[data-structured-category]");
      const empty = row.querySelector("[data-not-applicable]");
      const isRole = roleColumns.has(row.dataset.columnRow);
      metadata.disabled = isRole;
      structured.disabled = isRole;
      if (isRole) {
        metadata.checked = false;
        structured.checked = false;
      } else if (structured.checked) {
        metadata.checked = true;
      }
      category.disabled = isRole || !structured.checked;
      category.classList.toggle("d-none", category.disabled);
      empty.classList.toggle("d-none", !category.disabled);
    });
  };
  form.addEventListener("change", (event) => {
    const control = event.target;
    if (!(control instanceof HTMLInputElement)) return;
    if (control.matches("[data-structured-toggle]") && control.checked) {
      control.closest("tr").querySelector("[data-metadata-toggle]").checked = true;
    }
    if (control.matches("[data-metadata-toggle]") && !control.checked) {
      control.closest("tr").querySelector("[data-structured-toggle]").checked = false;
    }
    if (control.type === "radio" || control.hasAttribute("data-metadata-toggle") || control.hasAttribute("data-structured-toggle")) {
      syncColumns();
    }
  });
  syncColumns();

  const toggleField = (element, show) => {
    if (!element) return;
    element.classList.toggle("d-none", !show);
    element.querySelectorAll("input, select, textarea").forEach((control) => { control.disabled = !show; });
  };
  const syncReplacementRow = (row) => {
    const method = row.querySelector("[data-replacement]").value;
    const usesConsistency = ["faker", "custom_list"].includes(method);
    toggleField(row.querySelector("[data-consistency-setting]"), usesConsistency);
    toggleField(row.querySelector("[data-list-setting]"), method === "custom_list");
    row.querySelectorAll("[data-date-setting]").forEach((element) => element.classList.toggle("d-none", method !== "date_shift"));
    row.querySelector("[data-no-consistency]")?.classList.toggle("d-none", usesConsistency || method === "date_shift");
  };
  const syncReplacements = () => {
    form.querySelectorAll("[data-policy-row]").forEach(syncReplacementRow);
    const dateMethod = form.querySelector('[name="replacement:DATE"]')?.value;
    toggleField(form.querySelector("[data-date-range]"), dateMethod === "date_shift");
  };
  form.addEventListener("change", (event) => {
    if (event.target.matches?.("[data-replacement]")) syncReplacements();
  });
  syncReplacements();

  const validation = document.getElementById("validation-enabled");
  const reviewNone = document.getElementById("review-none");
  const reviewFindings = document.getElementById("review-findings");
  const syncValidation = () => {
    const enabled = validation.checked;
    reviewNone.disabled = enabled;
    reviewFindings.disabled = !enabled;
    if (enabled && reviewNone.checked) reviewFindings.checked = true;
    if (!enabled && reviewFindings.checked) reviewNone.checked = true;
  };
  validation.addEventListener("change", syncValidation);
  syncValidation();

  const jsonButton = document.getElementById("view-configuration-json");
  jsonButton?.addEventListener("click", async () => {
    const error = document.getElementById("configuration-json-error");
    try {
      const response = await fetch(form.dataset.configurationJsonUrl, {
        method: "POST",
        body: new FormData(form),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Configuration could not be generated.");
      document.getElementById("configuration-json-view").textContent = JSON.stringify(payload, null, 2);
      bootstrap.Modal.getOrCreateInstance(document.getElementById("configuration-json-dialog")).show();
      error.classList.add("d-none");
    } catch (caught) {
      error.textContent = caught.message;
      error.classList.remove("d-none");
    }
  });

  const rulesField = document.getElementById("rules-json");
  const rulesToggle = document.getElementById("rules-enabled");
  const ruleList = document.getElementById("rule-list");
  const ruleCount = document.getElementById("rule-count");
  const rulesView = document.getElementById("rules-json-view");
  const viewRules = document.getElementById("view-rules-json");
  const downloadRules = document.getElementById("download-rules");
  const nameField = document.getElementById("rule-name");
  const categoryField = document.getElementById("rule-category");
  const typeField = document.getElementById("rule-type");
  const patternField = document.getElementById("rule-pattern");
  const ignoreCaseField = document.getElementById("rule-ignore-case");
  let payload;
  try { payload = JSON.parse(rulesField.value || '{"rules":[]}'); } catch { payload = { rules: [] }; }
  if (!Array.isArray(payload?.rules)) payload = { rules: [] };
  let editing = null;

  const resetEditor = () => {
    editing = null;
    nameField.value = "";
    patternField.value = "";
    typeField.value = "exact";
    ignoreCaseField.checked = false;
    document.getElementById("rule-editor-heading").textContent = "Add rule";
    document.getElementById("save-rule").textContent = "Add rule";
  };
  const drawRules = () => {
    rulesField.value = JSON.stringify(payload);
    ruleCount.textContent = `${payload.rules.length} rule${payload.rules.length === 1 ? "" : "s"}`;
    rulesView.textContent = JSON.stringify(payload, null, 2);
    viewRules.disabled = payload.rules.length === 0;
    downloadRules.disabled = payload.rules.length === 0;
    ruleList.replaceChildren();
    if (!payload.rules.length) {
      const empty = document.createElement("div");
      empty.className = "list-group-item text-secondary";
      empty.textContent = "No custom rules.";
      ruleList.append(empty);
      return;
    }
    payload.rules.forEach((rule, index) => {
      const item = document.createElement("div");
      item.className = "list-group-item d-flex justify-content-between align-items-start gap-3";
      const text = document.createElement("div");
      text.innerHTML = `<div class="fw-semibold"></div><small class="text-secondary font-monospace"></small>`;
      text.firstElementChild.textContent = `${rule.name} · ${rule.category}`;
      text.lastElementChild.textContent = `${rule.type}: ${rule.pattern}`;
      const buttons = document.createElement("div");
      buttons.className = "btn-group btn-group-sm";
      const edit = document.createElement("button");
      edit.className = "btn btn-outline-primary";
      edit.type = "button";
      edit.textContent = "Edit";
      edit.addEventListener("click", () => {
        editing = index;
        nameField.value = rule.name;
        categoryField.value = rule.category;
        typeField.value = rule.type;
        patternField.value = rule.pattern;
        ignoreCaseField.checked = Boolean(rule.ignore_case);
        document.getElementById("rule-editor-heading").textContent = "Edit rule";
        document.getElementById("save-rule").textContent = "Save";
      });
      const remove = document.createElement("button");
      remove.className = "btn btn-outline-danger";
      remove.type = "button";
      remove.textContent = "Remove";
      remove.addEventListener("click", () => { payload.rules.splice(index, 1); resetEditor(); drawRules(); });
      buttons.append(edit, remove);
      item.append(text, buttons);
      ruleList.append(item);
    });
  };
  document.getElementById("save-rule").addEventListener("click", () => {
    const name = nameField.value.trim();
    const pattern = patternField.value;
    if (!name || !pattern) return window.alert("Enter a rule name and text or expression.");
    if (typeField.value === "regex") {
      try { new RegExp(pattern); } catch (error) { return window.alert(`Invalid regular expression: ${error.message}`); }
    }
    const rule = {
      id: editing === null ? `rule-${crypto.getRandomValues(new Uint32Array(1))[0].toString(16)}` : payload.rules[editing].id,
      name,
      category: categoryField.value,
      type: typeField.value,
      pattern,
      ignore_case: ignoreCaseField.checked,
    };
    if (editing === null) payload.rules.push(rule); else payload.rules[editing] = rule;
    rulesToggle.checked = true;
    resetEditor();
    drawRules();
  });
  document.getElementById("new-rule").addEventListener("click", resetEditor);
  document.getElementById("rules-file")?.addEventListener("change", async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const body = new FormData();
    body.append("rules_file", file);
    body.append("csrf_token", form.querySelector('[name="csrf_token"]').value);
    const status = document.getElementById("rules-import-status");
    try {
      const response = await fetch(form.dataset.rulesImportUrl, { method: "POST", body });
      const imported = await response.json();
      if (!response.ok) throw new Error(imported.error || "Rules could not be imported.");
      payload = imported.rules;
      rulesToggle.checked = true;
      drawRules();
      status.textContent = `${imported.count} rules imported from ${imported.source_name}.`;
      status.classList.remove("text-danger");
    } catch (error) {
      status.textContent = error.message;
      status.classList.add("text-danger");
    }
    event.target.value = "";
  });
  resetEditor();
  drawRules();
})();
