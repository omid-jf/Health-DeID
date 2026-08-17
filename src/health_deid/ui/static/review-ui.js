"use strict";

(() => {
  const editor = document.getElementById("review-editor");
  const source = document.getElementById("review-source");
  const output = document.getElementById("review-output");
  const eventField = document.getElementById("span-events");
  const structuredField = document.getElementById("structured-events");
  const eventList = document.getElementById("pending-events");
  const form = document.getElementById("review-decision");
  if (
    !editor ||
    !source ||
    !output ||
    !eventField ||
    !structuredField ||
    !eventList ||
    !form
  )
    return;

  const parseData = (name, fallback) => {
    try {
      return JSON.parse(editor.dataset[name] || JSON.stringify(fallback));
    } catch (_error) {
      return fallback;
    }
  };
  const sourceText = parseData("sourceText", "");
  const sourcePoints = Array.from(sourceText);
  const groups = parseData("spanGroups", []);
  const workspace = parseData("workspace", {});
  const policy = parseData("policy", {});
  const placeholders = parseData("placeholders", {});
  const categoryColors = parseData("categoryColors", {});
  let events = Array.isArray(workspace.span_events)
    ? workspace.span_events.map((item) => ({ ...item }))
    : [];
  let structuredEvents = Array.isArray(workspace.structured_events)
    ? workspace.structured_events.map((item) => ({ ...item }))
    : [];
  const history = [];
  let previewSequence = 0;
  let previewTimer;
  let phiCursor = -1;

  const eventId = (operation) =>
    `${operation}-${Date.now()}-${crypto.getRandomValues(new Uint32Array(1))[0].toString(16)}`;
  const snapshot = () => ({
    spans: events.map((item) => ({
      ...item,
      finding_ids: [...(item.finding_ids || [])],
    })),
    structured: structuredEvents.map((item) => ({ ...item })),
  });
  const pushHistory = () => history.push(snapshot());
  const removedGroupIds = () =>
    new Set(
      events
        .filter((item) => ["remove", "modify"].includes(item.operation))
        .map((item) => item.group_id),
    );

  const effectiveHighlights = () => {
    const removed = removedGroupIds();
    const highlights = groups
      .filter((group) => !removed.has(group.group_id))
      .map((group) => ({
        category: group.category,
        start: Number(group.start_char),
        end: Number(group.end_char),
        groupId: group.group_id,
        findingIds: [...(group.finding_ids || [])],
        eventIds: [],
      }));
    events
      .filter((item) => ["add", "modify"].includes(item.operation))
      .forEach((item) => {
        highlights.push({
          category: item.category,
          start: Number(item.start_char),
          end: Number(item.end_char),
          groupId: null,
          findingIds: [],
          eventIds: [item.event_id],
        });
      });
    highlights.sort(
      (left, right) => left.start - right.start || right.end - left.end,
    );
    return highlights;
  };

  const appendText = (parent, start, end) =>
    parent.append(
      document.createTextNode(sourcePoints.slice(start, end).join("")),
    );
  const renderSource = () => {
    source.replaceChildren();
    let cursor = 0;
    effectiveHighlights().forEach((highlight) => {
      if (highlight.start < cursor) return;
      appendText(source, cursor, highlight.start);
      const mark = document.createElement("button");
      mark.type = "button";
      const color = categoryColors[highlight.category] || "secondary";
      mark.className = `phi-mark bg-${color}-subtle border-${color} text-${color}-emphasis`;
      mark.dataset.groupId = highlight.groupId || "";
      mark.dataset.findingIds = JSON.stringify(highlight.findingIds);
      mark.dataset.eventIds = JSON.stringify(highlight.eventIds);
      mark.dataset.category = highlight.category;
      mark.dataset.phiLabel = String(highlight.category).replaceAll("_", " ");
      mark.setAttribute(
        "aria-label",
        `${String(highlight.category).replaceAll("_", " ")}: ${sourcePoints.slice(highlight.start, highlight.end).join("")}. Click to remove.`,
      );
      mark.title = `Remove ${String(highlight.category).replaceAll("_", " ")}`;
      appendText(mark, highlight.start, highlight.end);
      source.append(mark);
      cursor = highlight.end;
    });
    appendText(source, cursor, sourcePoints.length);
  };

  const describeSpan = (item) => {
    const category = String(item.category || "PHI").replaceAll("_", " ");
    if (item.operation === "remove") {
      const group = groups.find(
        (candidate) => candidate.group_id === item.group_id,
      );
      const text = group
        ? sourcePoints.slice(group.start_char, group.end_char).join("")
        : "selected PHI";
      return `Remove ${group ? String(group.category).replaceAll("_", " ") : category}: ${text}`;
    }
    if (item.operation === "modify")
      return `Change to ${category}: ${item.text}`;
    return `Add ${category}: ${item.text}`;
  };
  const renderEvents = () => {
    eventField.value = JSON.stringify(events);
    structuredField.value = JSON.stringify(structuredEvents);
    eventList.replaceChildren();
    const descriptions = [
      ...events.map(describeSpan),
      ...structuredEvents.map(
        (item) =>
          `Change ${item.column_name}: ${JSON.stringify(item.original_value)} → ${JSON.stringify(item.replacement_value)}`,
      ),
    ];
    if (!descriptions.length) descriptions.push("No PHI changes");
    descriptions.forEach((description) => {
      const item = document.createElement("li");
      item.textContent = description;
      eventList.append(item);
    });
  };

  const sameValue = (left, right) =>
    JSON.stringify(left) === JSON.stringify(right);
  const displayValue = (value) => {
    if (value === null) return "null";
    if (typeof value === "string") return value;
    return JSON.stringify(value);
  };
  const replacementForRow = (row) => {
    const action = row.querySelector("[data-structured-action]").value;
    if (action === "redact") return placeholders[row.dataset.category];
    if (action === "original") return JSON.parse(row.dataset.original);
    if (action === "custom")
      return row.querySelector("[data-structured-custom]").value;
    return JSON.parse(row.dataset.baseline);
  };
  const configureStructuredRow = (row) => {
    const action = row.querySelector("[data-structured-action]");
    const custom = row.querySelector("[data-structured-custom]");
    const saved = structuredEvents.find(
      (item) => item.column_name === row.dataset.column,
    );
    let selected = "baseline";
    if (saved) {
      if (sameValue(saved.replacement_value, JSON.parse(row.dataset.original)))
        selected = "original";
      else if (
        sameValue(saved.replacement_value, placeholders[row.dataset.category])
      )
        selected = "redact";
      else {
        selected = "custom";
        custom.value = displayValue(saved.replacement_value);
      }
    }
    action.value = selected;
    custom.hidden = selected !== "custom";
  };
  const restoreStructuredControls = () => {
    document
      .querySelectorAll("[data-structured-field]")
      .forEach(configureStructuredRow);
  };
  const syncStructured = () => {
    const prior = new Map(
      structuredEvents.map((item) => [item.column_name, item]),
    );
    structuredEvents = [];
    document.querySelectorAll("[data-structured-field]").forEach((row) => {
      const baseline = JSON.parse(row.dataset.baseline);
      const original = JSON.parse(row.dataset.original);
      const replacement = replacementForRow(row);
      if (sameValue(baseline, replacement)) return;
      structuredEvents.push({
        event_id:
          prior.get(row.dataset.column)?.event_id || eventId("structured"),
        column_name: row.dataset.column,
        category: row.dataset.category,
        original_value: original,
        replacement_value: replacement,
      });
    });
  };

  const requestPreview = async () => {
    const sequence = ++previewSequence;
    output.classList.add("opacity-50");
    try {
      const response = await fetch(editor.dataset.previewUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": editor.dataset.csrf,
        },
        body: JSON.stringify({
          span_events: events,
          structured_events: structuredEvents,
        }),
      });
      const payload = await response.json();
      if (!response.ok)
        throw new Error(payload.error || "Preview could not be generated.");
      if (sequence === previewSequence) {
        output.textContent = payload.text;
        output.classList.remove("text-danger");
        document.querySelectorAll("[data-structured-field]").forEach((row) => {
          const value = payload.structured_fields?.[row.dataset.column];
          row.querySelector("[data-structured-preview]").textContent =
            displayValue(value);
        });
      }
    } catch (error) {
      if (sequence === previewSequence) {
        output.textContent = `Preview unavailable: ${error.message}`;
        output.classList.add("text-danger");
      }
    } finally {
      if (sequence === previewSequence) output.classList.remove("opacity-50");
    }
  };
  const schedulePreview = () => {
    window.clearTimeout(previewTimer);
    previewTimer = window.setTimeout(requestPreview, 180);
  };
  const refresh = () => {
    renderSource();
    renderEvents();
    schedulePreview();
  };

  source.addEventListener("click", (click) => {
    const mark = click.target.closest(".phi-mark");
    if (!mark) return;
    pushHistory();
    const selectedEventIds = new Set(JSON.parse(mark.dataset.eventIds || "[]"));
    if (selectedEventIds.size) {
      events = events.filter((item) => !selectedEventIds.has(item.event_id));
    } else if (
      mark.dataset.groupId &&
      !removedGroupIds().has(mark.dataset.groupId)
    ) {
      events.push({
        event_id: eventId("remove"),
        operation: "remove",
        group_id: mark.dataset.groupId,
        finding_ids: JSON.parse(mark.dataset.findingIds || "[]"),
        reason_code: "manual_review",
      });
    }
    refresh();
  });

  const selectedOffsets = () => {
    const selection = window.getSelection();
    if (!selection || selection.rangeCount === 0 || selection.isCollapsed)
      return null;
    const range = selection.getRangeAt(0);
    if (
      !source.contains(range.startContainer) ||
      !source.contains(range.endContainer)
    )
      return null;
    const prefix = document.createRange();
    prefix.selectNodeContents(source);
    prefix.setEnd(range.startContainer, range.startOffset);
    const start = Array.from(prefix.toString()).length;
    const selectedText = range.toString();
    const end = start + Array.from(selectedText).length;
    return end > start ? { start, end, selection, text: selectedText } : null;
  };
  document.querySelectorAll(".category-button").forEach((button) => {
    button.addEventListener("click", () => {
      const selected = selectedOffsets();
      if (!selected)
        return window.alert("Select exact text inside the source first.");
      if (
        button.dataset.category === "AGE" &&
        policy.categories?.AGE?.action === "generalize"
      ) {
        const age = Number.parseInt(selected.text.match(/\d+/)?.[0] || "", 10);
        if (
          Number.isFinite(age) &&
          age < 90 &&
          !window.confirm(
            "AGE is configured for Safe Harbor generalization. This age is below 90, so the reviewed output will remain unchanged. Add it anyway?",
          )
        )
          return;
      }
      pushHistory();
      events.push({
        event_id: eventId("add"),
        operation: "add",
        category: button.dataset.category,
        text: sourcePoints.slice(selected.start, selected.end).join(""),
        start_char: selected.start,
        end_char: selected.end,
        reason_code: "manual_review",
      });
      selected.selection.removeAllRanges();
      refresh();
    });
  });

  document.querySelectorAll("[data-structured-action]").forEach((select) => {
    select.addEventListener("change", () => {
      pushHistory();
      const row = select.closest("[data-structured-field]");
      row.querySelector("[data-structured-custom]").hidden =
        select.value !== "custom";
      syncStructured();
      renderEvents();
      schedulePreview();
      if (select.value === "custom")
        row.querySelector("[data-structured-custom]").focus();
    });
  });
  document.querySelectorAll("[data-structured-custom]").forEach((input) => {
    input.addEventListener("change", () => {
      pushHistory();
      syncStructured();
      renderEvents();
      schedulePreview();
    });
  });
  document.getElementById("undo-change")?.addEventListener("click", () => {
    if (!history.length) return;
    const prior = history.pop();
    events = prior.spans;
    structuredEvents = prior.structured;
    restoreStructuredControls();
    refresh();
  });
  document.getElementById("reset-changes")?.addEventListener("click", () => {
    if (!events.length && !structuredEvents.length) return;
    pushHistory();
    events = [];
    structuredEvents = [];
    restoreStructuredControls();
    refresh();
  });
  document.getElementById("next-phi")?.addEventListener("click", () => {
    const marks = [...source.querySelectorAll(".phi-mark")];
    if (!marks.length) return;
    phiCursor = (phiCursor + 1) % marks.length;
    marks[phiCursor].focus();
    marks[phiCursor].scrollIntoView({ block: "center", behavior: "smooth" });
  });
  form.addEventListener("submit", () => {
    syncStructured();
    renderEvents();
  });

  const timerCard = document.getElementById("review-timer");
  const timerValue = document.getElementById("timer-value");
  const timerToggle = document.getElementById("timer-toggle");
  if (timerCard && timerValue && timerToggle) {
    let seconds = Number(timerCard.dataset.seconds || 0);
    let running = timerCard.dataset.running === "true";
    const formatTime = (value) =>
      [
        Math.floor(value / 3600),
        Math.floor((value % 3600) / 60),
        Math.floor(value % 60),
      ]
        .map((part) => String(part).padStart(2, "0"))
        .join(":");
    const parseTime = (value) => {
      const match = String(value)
        .trim()
        .match(/^(\d+):([0-5]\d):([0-5]\d)$/);
      return match
        ? Number(match[1]) * 3600 + Number(match[2]) * 60 + Number(match[3])
        : null;
    };
    const paintTimer = () => {
      if (document.activeElement !== timerValue)
        timerValue.value = formatTime(seconds);
      timerToggle.textContent = running ? "Pause" : "Start";
    };
    const updateTimer = async (action, extra = {}) => {
      const controls = timerCard.querySelectorAll("button, input");
      controls.forEach((control) => {
        control.disabled = true;
      });
      try {
        const response = await fetch(timerCard.dataset.url, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            csrf_token: timerCard.dataset.csrf,
            action,
            ...extra,
          }),
        });
        const payload = await response.json();
        if (!response.ok)
          throw new Error(payload.error || "Timer could not be updated.");
        seconds = Number(payload.review_seconds || 0);
        running = Boolean(payload.running);
        paintTimer();
      } catch (error) {
        window.alert(error.message);
      } finally {
        controls.forEach((control) => {
          control.disabled = false;
        });
      }
    };
    window.setInterval(() => {
      if (running) {
        seconds += 1;
        paintTimer();
      }
    }, 1000);
    timerToggle.addEventListener("click", () =>
      updateTimer(running ? "pause" : "start"),
    );
    document
      .getElementById("timer-minus")
      ?.addEventListener("click", () =>
        updateTimer("adjust", { delta_seconds: "-60" }),
      );
    document
      .getElementById("timer-plus")
      ?.addEventListener("click", () =>
        updateTimer("adjust", { delta_seconds: "60" }),
      );
    document
      .getElementById("timer-restart")
      ?.addEventListener("click", () => updateTimer("restart"));
    timerValue.addEventListener("change", () => {
      const entered = parseTime(timerValue.value);
      if (entered === null) {
        window.alert("Enter review time as HH:MM:SS.");
        paintTimer();
        return;
      }
      updateTimer("set", { seconds: String(entered) });
    });
    window.addEventListener("pagehide", () => {
      if (running)
        navigator.sendBeacon(
          timerCard.dataset.url,
          new URLSearchParams({
            csrf_token: timerCard.dataset.csrf,
            action: "pause",
          }),
        );
    });
    paintTimer();
  }

  restoreStructuredControls();
  refresh();
})();
