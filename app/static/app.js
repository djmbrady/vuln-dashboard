const SEVERITY_COLORS = {
  CRITICAL: "#9f1239",
  HIGH: "#c2410c",
  MEDIUM: "#a16207",
  LOW: "#1d4ed8",
  UNKNOWN: "#78716c",
};
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
const SOURCE_LABELS = {
  container: "CI image",
  manifest: "Repository",
};

const charts = {};

function sourceLabel(scanType) {
  return SOURCE_LABELS[scanType] || scanType || "Unknown";
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

function destroyChart(id) {
  if (charts[id]) {
    charts[id].destroy();
    delete charts[id];
  }
}

function showEmpty(canvasId, message) {
  destroyChart(canvasId);
  const canvas = document.getElementById(canvasId);
  const box = canvas.parentElement;
  let note = box.querySelector(".empty");
  if (!note) {
    note = el("p", "empty");
    box.appendChild(note);
  }
  note.hidden = false;
  note.textContent = message;
  canvas.hidden = true;
}

function showChart(canvasId, config) {
  const canvas = document.getElementById(canvasId);
  const note = canvas.parentElement.querySelector(".empty");
  if (note) note.hidden = true;
  canvas.hidden = false;
  destroyChart(canvasId);
  charts[canvasId] = new Chart(canvas, config);
}

function stackedSeverity(labels, rows, labelKey) {
  return {
    type: "bar",
    data: {
      labels,
      datasets: SEVERITIES.map((severity) => ({
        label: severity,
        data: rows.map((row) => row[severity] || 0),
        backgroundColor: SEVERITY_COLORS[severity],
        stack: "severity",
      })),
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: "bottom" } },
      scales: {
        x: { stacked: true, ticks: { callback: function (value) {
          const label = this.getLabelForValue(value);
          return labelKey === "repo" && label.length > 28 ? label.slice(0, 26) + "…" : label;
        } } },
        y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } },
      },
    },
  };
}

function renderKpis(kpis) {
  const items = [
    ["Findings in view", kpis.findings, `${kpis.open_findings} still open`],
    ["High or critical", kpis.critical_high, `${kpis.critical_high_with_fix} have a fix listed`],
    ["Repositories", kpis.repositories, "in the current view"],
    ["Fix listed", `${kpis.fix_available_pct}%`, `${kpis.fix_available} of ${kpis.findings}`],
  ];
  const root = document.getElementById("kpis");
  root.replaceChildren();
  for (const [label, value, detail] of items) {
    const card = el("article", "kpi");
    card.append(el("span", null, label), el("strong", null, String(value)), el("em", null, detail));
    root.appendChild(card);
  }
}

function renderCharts(data) {
  if (!data.by_severity.length) {
    showEmpty("severityChart", "No findings in this view.");
  } else {
    showChart("severityChart", {
      type: "doughnut",
      data: {
        labels: data.by_severity.map((item) => item.severity),
        datasets: [{
          data: data.by_severity.map((item) => item.count),
          backgroundColor: data.by_severity.map((item) => SEVERITY_COLORS[item.severity]),
        }],
      },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: "bottom" } } },
    });
  }

  const fixCounts = data.by_fix.map((item) => item.count);
  if (fixCounts.every((count) => count === 0)) {
    showEmpty("fixChart", "No findings in this view.");
  } else {
    showChart("fixChart", {
      type: "doughnut",
      data: {
        labels: data.by_fix.map((item) => item.label),
        datasets: [{ data: fixCounts, backgroundColor: ["#0f766e", "#a8a29e"] }],
      },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: "bottom" } } },
    });
  }

  if (!data.by_scan_type.length) {
    showEmpty("sourceChart", "No findings in this view.");
  } else {
    showChart("sourceChart", {
      type: "bar",
      data: {
        labels: data.by_scan_type.map((item) => sourceLabel(item.scan_type)),
        datasets: [{
          label: "Findings",
          data: data.by_scan_type.map((item) => item.count),
          backgroundColor: ["#1f6f78", "#12343f"],
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
      },
    });
  }

  if (!data.by_repository.length) {
    showEmpty("repoChart", "No findings in this view.");
  } else {
    showChart("repoChart", stackedSeverity(
      data.by_repository.map((item) => item.repo),
      data.by_repository,
      "repo",
    ));
  }

  showChart("ageChart", stackedSeverity(
    data.by_age.map((item) => item.bucket),
    data.by_age,
    "age",
  ));
}

function renderTable(findings) {
  const body = document.getElementById("findings");
  body.replaceChildren();
  document.getElementById("tableCount").textContent = findings.length === 1
    ? "1 finding"
    : `${findings.length} findings`;

  if (!findings.length) {
    const row = el("tr");
    const cell = el("td", "empty", "Nothing matches these filters.");
    cell.colSpan = 8;
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }

  for (const finding of findings) {
    const row = el("tr");
    const severity = el("td");
    severity.appendChild(el("span", `chip sev-${finding.severity}`, finding.severity));
    const repo = el("td");
    repo.appendChild(el("div", "package", finding.repo_full_name));
    if (finding.branch) repo.appendChild(el("div", "muted", finding.branch));
    const source = el("td");
    source.appendChild(el("div", null, sourceLabel(finding.scan_type)));
    if (finding.image_tag) source.appendChild(el("div", "muted", finding.image_tag));

    row.append(
      severity,
      repo,
      el("td", null, finding.package_name || "—"),
      el("td", null, finding.installed_version || "—"),
      el("td", null, finding.fixed_version || "None listed"),
      el("td", null, finding.cve_id || "—"),
      el("td", null, finding.age_label),
      source,
    );
    body.appendChild(row);

    if (finding.title || finding.mitigation) {
      const detail = el("tr", "detail");
      const cell = el("td");
      cell.colSpan = 8;
      const parts = [finding.title, finding.mitigation].filter(Boolean);
      cell.textContent = parts.join(" — ");
      detail.appendChild(cell);
      body.appendChild(detail);
    }
  }
}

function fillSelect(select, values, current, allLabel) {
  const previous = current;
  select.replaceChildren(new Option(allLabel, ""));
  for (const value of values) {
    const label = select.id === "scanType" ? sourceLabel(value) : value;
    select.appendChild(new Option(label, value));
  }
  if ([...select.options].some((option) => option.value === previous)) {
    select.value = previous;
  }
}

function render(data) {
  document.getElementById("error").hidden = true;
  const generated = new Date(data.generated_at);
  const latest = data.kpis.latest_scan_at
    ? ` Latest scan ${new Date(data.kpis.latest_scan_at).toLocaleString()}.`
    : "";
  document.getElementById("generated").textContent = `Updated ${generated.toLocaleString()}.${latest}`;
  document.getElementById("narrative").textContent = data.narrative;

  fillSelect(document.getElementById("repo"), data.filters.repos, data.filters.applied.repo || "", "All repositories");
  fillSelect(
    document.getElementById("severity"),
    data.filters.severities,
    data.filters.applied.severity || "",
    "All severities",
  );
  const status = document.getElementById("status");
  const selectedStatus = data.filters.applied.status || "all";
  const statuses = [...new Set(["open", ...data.filters.statuses])].sort((a, b) => {
    if (a === "open") return -1;
    if (b === "open") return 1;
    return a.localeCompare(b);
  });
  status.replaceChildren(new Option("All statuses", "all"));
  for (const value of statuses) {
    status.appendChild(new Option(value === "open" ? "Open" : value, value));
  }
  status.value = selectedStatus;
  document.getElementById("scanType").value = data.filters.applied.scan_type || "";

  renderKpis(data.kpis);
  renderCharts(data);
  renderTable(data.findings);
}

function queryParams(refresh) {
  const params = new URLSearchParams();
  for (const [id, name] of [["repo", "repo"], ["severity", "severity"], ["status", "status"], ["scanType", "scan_type"]]) {
    const value = document.getElementById(id).value;
    if (value) params.set(name, value);
  }
  if (refresh) params.set("refresh", "true");
  return params;
}

let requestId = 0;

async function load(refresh) {
  const id = ++requestId;
  const error = document.getElementById("error");
  error.hidden = true;
  try {
    const response = await fetch(`/api/dashboard?${queryParams(refresh)}`);
    const body = await response.json();
    if (id !== requestId) return;
    if (!response.ok) {
      const detail = body.detail;
      throw new Error(typeof detail === "string" ? detail : "The dashboard could not load findings.");
    }
    render(body);
  } catch (err) {
    if (id !== requestId) return;
    error.hidden = false;
    error.textContent = err.message;
  }
}

document.getElementById("filters").addEventListener("change", () => load(false));
document.getElementById("refresh").addEventListener("click", () => load(true));
load(false);
