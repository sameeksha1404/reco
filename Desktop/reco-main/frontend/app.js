const API_BASE = "http://127.0.0.1:8000";

const state = {
  threats: [],
  controls: [],
  selectedThreats: [],
  selections: [],
  currentIndex: 0,
  selectedControls: [],
  selectedThreatIds: [],
  coverageSelectedControlIds: [],
  controlThreatMap: {},
  coverageLoaded: false,
};

// --- DOM References ---
const threatListEl = document.getElementById("threat-list");
const threatSearchEl = document.getElementById("threat-search");
const clearSearchBtn = document.getElementById("clear-search");
const resetFiltersBtn = document.getElementById("reset-filters");
const categoryFilterEl = document.getElementById("category-filter");
const sortSelectEl = document.getElementById("sort-select");
const selectionView = document.getElementById("selection-view");
const analysisView = document.getElementById("analysis-view");
const resultView = document.getElementById("result-view");
const startBtn = document.getElementById("start-btn");
const restartBtn = document.getElementById("restart-btn");
const exportBtn = document.getElementById("export-btn");
const stepLabel = document.getElementById("step-label");
const activeThreatName = document.getElementById("active-threat-name");
const activePriority = document.getElementById("active-priority");
const activeCategoryBadge = document.getElementById("active-category-badge");
const activeWeightBadge = document.getElementById("active-weight-badge");
const progressText = document.getElementById("progress-text"); // Use label if available
const progressFill = document.getElementById("progress-fill");
const controlListEl = document.getElementById("control-list");
const riskScoreEl = document.getElementById("risk-score");
const riskLevelEl = document.getElementById("risk-level");
const responsePriorityEl = document.getElementById("response-priority");
const threatCountEl = document.getElementById("threat-count");
const controlCountEl = document.getElementById("control-count");
const threatSelectedCountEl = document.getElementById("threat-selected-count");
const threatTotalCountEl = document.getElementById("threat-total-count");
const analysisSummaryEl = document.getElementById("analysis-summary");
const analysisDashboardEl = document.getElementById("analysis-dashboard");
const toastContainerEl = document.getElementById("toast-container");

// Coverage Refs
const controlSelectorGrid = document.getElementById("control-selector-grid");
const coverageDetail = document.getElementById("coverage-detail");
const covControlName = document.getElementById("cov-control-name");

// --- Helper Functions ---
async function fetchJSON(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  const contentType = res.headers.get("content-type") || "";
  const data = contentType.includes("application/json") ? await res.json() : await res.text();

  if (!res.ok) {
    const message = typeof data === "object" ? (data.detail || data.message || `Request failed: ${res.status}`) : (data || `Request failed: ${res.status}`);
    const error = new Error(message);
    error.status = res.status;
    error.payload = data;
    throw error;
  }
  return data;
}

function showToast(message, type = "info") {
  if (!toastContainerEl) return;
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerHTML = `<i class="fas fa-${type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i> <span>${message}</span>`;
  toastContainerEl.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

function getPriority(weight) {
  if (weight >= 0.8) return "Critical";
  if (weight >= 0.65) return "High";
  if (weight >= 0.5) return "Medium";
  return "Low";
}

// --- UI Rendering ---

function updateSelectedCount() {
  const selectedCount = state.selectedThreatIds.length;
  threatSelectedCountEl.textContent = `${selectedCount} selected`;
  
  // Highlight cards
  document.querySelectorAll(".threat-item").forEach((card) => {
    const checkbox = card.querySelector("input[type='checkbox']");
    if (checkbox) {
      card.classList.toggle("selected", checkbox.checked);
    }
  });
}

function filterAndRenderThreats() {
  const searchTerm = threatSearchEl.value.trim().toLowerCase();
  const selectedCategory = categoryFilterEl.value;
  const sortOption = sortSelectEl.value;

  let filtered = state.threats.filter((t) => {
    const matchesSearch = !searchTerm || t.name.toLowerCase().includes(searchTerm) || t.category.toLowerCase().includes(searchTerm);
    const matchesCategory = !selectedCategory || t.category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  // Sorting
  if (sortOption === "priority-desc") filtered.sort((a, b) => b.weight - a.weight);
  else if (sortOption === "priority-asc") filtered.sort((a, b) => a.weight - b.weight);
  else if (sortOption === "name-asc") filtered.sort((a, b) => a.name.localeCompare(b.name));
  else if (sortOption === "name-desc") filtered.sort((a, b) => b.name.localeCompare(a.name));

  const grouped = filtered.reduce((acc, t) => {
    acc[t.category] = acc[t.category] || [];
    acc[t.category].push(t);
    return acc;
  }, {});

  threatListEl.innerHTML = "";
  
  Object.keys(grouped).sort().forEach(category => {
    const group = grouped[category];
    const selectedInCategory = group.filter(t => state.selectedThreatIds.includes(Number(t.id))).length;
    
    const groupDiv = document.createElement("div");
    groupDiv.className = "threat-category-group";
    groupDiv.innerHTML = `
      <div class="threat-category-header">
        <div>
          <h3 class="threat-category-title">${category}</h3>
          <p class="category-subtitle">${selectedInCategory} selected of ${group.length}</p>
        </div>
        <div class="category-actions">
          <button class="mini-action" onclick="bulkSelect('${category}', true)">Select visible</button>
          <button class="mini-action muted" onclick="bulkSelect('${category}', false)">Clear</button>
          <span class="threat-category-count">${group.length}</span>
        </div>
      </div>
      <div class="threat-grid"></div>
    `;

    const grid = groupDiv.querySelector(".threat-grid");
    group.forEach(threat => {
      const priority = getPriority(threat.weight);
      const isChecked = state.selectedThreatIds.includes(Number(threat.id));
      const card = document.createElement("label");
      card.className = `threat-item ${isChecked ? 'selected' : ''}`;
      card.innerHTML = `
        <div class="threat-top">
          <span class="category-chip">${threat.category}</span>
          <input type="checkbox" value="${threat.id}" ${isChecked ? 'checked' : ''} onchange="toggleThreat(${threat.id}, this.checked)">
        </div>
        <div class="threat-title">${threat.name}</div>
        <div class="threat-bottom">
          <span class="priority-chip priority-${priority.toLowerCase()}">${priority}</span>
          <span class="weight-badge">W: ${Number(threat.weight).toFixed(2)}</span>
        </div>
      `;
      grid.appendChild(card);
    });
    threatListEl.appendChild(groupDiv);
  });
  
  updateSelectedCount();
}

// --- Global Functions for DOM events ---
window.toggleThreat = (id, checked) => {
  id = Number(id);
  if (checked) {
    if (!state.selectedThreatIds.includes(id)) state.selectedThreatIds.push(id);
  } else {
    state.selectedThreatIds = state.selectedThreatIds.filter(sid => sid !== id);
  }
  filterAndRenderThreats();
};

window.bulkSelect = (category, shouldSelect) => {
  const visibleInCategory = state.threats.filter(t => t.category === category);
  visibleInCategory.forEach(t => {
    const tid = Number(t.id);
    if (shouldSelect) {
      if (!state.selectedThreatIds.includes(tid)) state.selectedThreatIds.push(tid);
    } else {
      state.selectedThreatIds = state.selectedThreatIds.filter(sid => sid !== tid);
    }
  });
  filterAndRenderThreats();
};

// --- Analysis Workflow ---

async function startAnalysis() {
  state.selectedThreats = state.threats.filter(t => state.selectedThreatIds.includes(Number(t.id)));
  if (state.selectedThreats.length === 0) {
    showToast("Select at least one threat to begin.", "error");
    return;
  }
  state.currentIndex = 0;
  state.selections = [];
  selectionView.classList.add("hidden");
  analysisView.classList.remove("hidden");
  renderStep();
}

async function renderStep() {
  const threat = state.selectedThreats[state.currentIndex];
  const priority = getPriority(threat.weight);
  
  stepLabel.textContent = `Analyzing Threat ${state.currentIndex + 1} of ${state.selectedThreats.length}`;
  activeThreatName.textContent = threat.name;
  activePriority.textContent = priority;
  activePriority.className = `priority-pill badge-${priority.toLowerCase()}`;
  activeCategoryBadge.textContent = threat.category;
  activeWeightBadge.textContent = Number(threat.weight).toFixed(2);
  
  const progress = ((state.currentIndex + 1) / state.selectedThreats.length) * 100;
  progressFill.style.width = `${progress}%`;
  if (progressText) progressText.textContent = `${state.currentIndex + 1} of ${state.selectedThreats.length} threats reviewed`;

  controlListEl.innerHTML = '<div class="loading-card"><div class="loading-line wide"></div><div class="loading-line"></div></div>';
  
  try {
    const controls = await fetchJSON(`/recommend-controls/${threat.id}`);
    renderControls(threat, controls);
  } catch (err) {
    showToast("Error loading controls", "error");
  }
}

function renderControls(threat, controls) {
  controlListEl.innerHTML = "";
  controls.forEach((c, idx) => {
    const btn = document.createElement("button");
    btn.className = `control-btn rank-${idx + 1}`;
    btn.innerHTML = `
      <div class="control-header">
        <div class="control-meta">
          <span class="control-rank">Recommendation #${idx + 1}</span>
          <h4>${c.name}</h4>
        </div>
        <span class="control-score">Effectiveness: ${Number(c.effectiveness).toFixed(2)}</span>
      </div>
      <div class="control-impact-text">${c.impact_text || 'Standard mitigation control for this threat pattern.'}</div>
      <div class="choose-label">Click to apply control →</div>
    `;
    btn.onclick = () => selectControl(threat.id, c.id, c.name, c.effectiveness);
    controlListEl.appendChild(btn);
  });
}

async function selectControl(threatId, controlId, controlName = "", effectiveness = 0, replaceExisting = false) {
  try {
    const saveResult = await fetchJSON("/saved-selection", {
      method: "POST",
      body: JSON.stringify({
        threat_id: Number(threatId),
        control_id: Number(controlId),
        replace_existing: Boolean(replaceExisting),
      }),
    });

    state.selections.push({
      threat_id: Number(threatId),
      control_id: Number(controlId),
      control_name: controlName || saveResult.control_name,
      effectiveness: Number(effectiveness || 0),
      impact: Number(saveResult.impact || 0),
      probability: Number(saveResult.probability || 0),
      risk_score: Number(saveResult.risk_score || 0),
      risk_level: saveResult.risk_level,
      saved_status: saveResult.replaced ? "replaced" : "saved",
    });

    showToast(saveResult.replaced ? "Already added earlier — replaced in database." : "Threat-control pair saved to database.", saveResult.replaced ? "warning" : "success");

    state.currentIndex++;
    if (state.currentIndex < state.selectedThreats.length) {
      renderStep();
    } else {
      finishAnalysis();
    }
  } catch (err) {
    if (err.status === 409) {
      showToast("This threat-control pair is already added. Tick the replace checkbox to update it.", "warning");
    } else {
      showToast(err.message || "Could not save selected pair to database.", "error");
    }
  }
}

async function finishAnalysis() {
  analysisView.classList.add("hidden");
  resultView.classList.remove("hidden");
  
  try {
    const result = await fetchJSON("/final-risk", {
      method: "POST",
      body: JSON.stringify({ selections: state.selections })
    });
    
    riskScoreEl.textContent = Number(result.risk_score).toFixed(3);
    riskLevelEl.textContent = result.risk_level;
    riskLevelEl.className = `risk-level-badge risk-${result.risk_level.toLowerCase()}`;
    if (responsePriorityEl) {
      const level = String(result.risk_level).toLowerCase();
      responsePriorityEl.textContent = level === 'high' ? 'Immediate Mitigation' : level === 'medium' ? 'Planned Remediation' : 'Routine Monitoring';
    }
    
    analysisSummaryEl.innerHTML = `
      <div class="summary-content">
        Analyzed <strong>${state.selectedThreats.length}</strong> threats. 
        Applied <strong>${state.selections.length}</strong> security controls. 
        Resulting in a <strong>${result.risk_level}</strong> risk posture.
      </div>
    `;
    buildAnalysisDashboard(result);
    showToast("Analysis Complete", "success");
  } catch (err) {
    showToast("Risk calculation failed", "error");
  }
}


async function loadCoverageData() {
  if (state.coverageLoaded) return;
  if (!controlSelectorGrid) return;

  controlSelectorGrid.innerHTML = `
    <div class="loading-card coverage-loading">
      <div class="loading-line wide"></div>
      <div class="loading-line"></div>
      <p>Loading controls and building control → threat coverage map...</p>
    </div>
  `;

  const uniqueControls = new Map();
  state.controlThreatMap = {};

  try {
    // Preferred endpoint, if your backend has it.
    const controls = await fetchJSON("/controls");
    if (Array.isArray(controls)) {
      controls.forEach(c => uniqueControls.set(Number(c.id), c));
    }
  } catch (err) {
    // Fallback below derives controls from recommendation output.
  }

  // Build the reverse mapping using the existing recommendation endpoint.
  // This keeps your backend functions/API flow the same and recreates the previous
  // "select control → show threats covered" behavior in the UI.
  for (const threat of state.threats) {
    try {
      const controls = await fetchJSON(`/recommend-controls/${threat.id}`);
      if (!Array.isArray(controls)) continue;

      controls.forEach(control => {
        const controlId = Number(control.id);
        uniqueControls.set(controlId, control);
        if (!state.controlThreatMap[controlId]) state.controlThreatMap[controlId] = [];

        const alreadyMapped = state.controlThreatMap[controlId].some(t => Number(t.id) === Number(threat.id));
        if (!alreadyMapped) {
          state.controlThreatMap[controlId].push({
            ...threat,
            control_effectiveness: Number(control.effectiveness || 0),
            control_name: control.name,
          });
        }
      });
    } catch (err) {
      // Continue mapping remaining threats even if one recommendation call fails.
    }
  }

  state.controls = Array.from(uniqueControls.values()).sort((a, b) => {
    const aCovered = state.controlThreatMap[Number(a.id)]?.length || 0;
    const bCovered = state.controlThreatMap[Number(b.id)]?.length || 0;
    return bCovered - aCovered || String(a.name).localeCompare(String(b.name));
  });

  state.coverageLoaded = true;
}

async function renderCoverageOverview() {
  if (!controlSelectorGrid) return;

  await loadCoverageData();

  if (!state.controls.length) {
    controlSelectorGrid.innerHTML = `
      <div class="empty-state-card">
        <i class="fa-solid fa-triangle-exclamation"></i>
        <h3>No controls found</h3>
        <p>Make sure your backend returns controls from /controls or /recommend-controls/{threat_id}.</p>
      </div>
    `;
    return;
  }

  const totalThreats = state.threats.length || 1;
  controlSelectorGrid.innerHTML = `
    <div class="coverage-toolbar">
      <div>
        <span class="step-badge">Control Selection</span>
        <h3>Select one or multiple controls</h3>
        <p>Covered threats will be calculated from the combined selected controls.</p>
      </div>
      <div class="coverage-toolbar-actions">
        <span class="count-pill" id="coverage-selected-count">${state.coverageSelectedControlIds.length} selected</span>
        <button class="btn btn-secondary" onclick="clearCoverageControls()">Clear</button>
      </div>
    </div>
    <div class="coverage-control-grid">
      ${state.controls.map((control, index) => {
        const id = Number(control.id);
        const covered = state.controlThreatMap[id]?.length || 0;
        const pct = Math.round((covered / totalThreats) * 100);
        const selected = state.coverageSelectedControlIds.includes(id);
        return `
          <label class="control-select-card ${selected ? 'selected' : ''}">
            <input type="checkbox" ${selected ? 'checked' : ''} onchange="toggleCoverageControl(${id}, this.checked)">
            <div class="coverage-card-top">
              <span class="coverage-rank">#${index + 1}</span>
              <span class="coverage-percent">${pct}%</span>
            </div>
            <h3>${control.name}</h3>
            <p>${covered} threats covered</p>
            <div class="mini-bar"><span style="width:${Math.min(100, pct)}%"></span></div>
          </label>
        `;
      }).join("")}
    </div>
  `;

  renderCoverageDetail();
}

window.toggleCoverageControl = (controlId, checked) => {
  controlId = Number(controlId);
  if (checked) {
    if (!state.coverageSelectedControlIds.includes(controlId)) state.coverageSelectedControlIds.push(controlId);
  } else {
    state.coverageSelectedControlIds = state.coverageSelectedControlIds.filter(id => id !== controlId);
  }
  renderCoverageOverview();
};

window.clearCoverageControls = () => {
  state.coverageSelectedControlIds = [];
  renderCoverageOverview();
};

function renderCoverageDetail() {
  if (!coverageDetail) return;
  coverageDetail.classList.remove("hidden");
  coverageDetail.classList.add("control-dashboard-shell");

  if (!state.coverageSelectedControlIds.length) {
    coverageDetail.innerHTML = `
      <div class="coverage-empty dashboard-empty">
        <i class="fa-solid fa-chart-pie"></i>
        <h3>Select controls to view the control analysis dashboard</h3>
        <p>The dashboard will show covered threats, domains, critical exposure, and control contribution.</p>
      </div>
    `;
    return;
  }

  const coveredThreatMap = new Map();
  const selectedControls = state.controls.filter(c => state.coverageSelectedControlIds.includes(Number(c.id)));

  state.coverageSelectedControlIds.forEach(controlId => {
    const threats = state.controlThreatMap[controlId] || [];
    const control = state.controls.find(c => Number(c.id) === Number(controlId));

    threats.forEach(threat => {
      const id = Number(threat.id);
      if (!coveredThreatMap.has(id)) {
        coveredThreatMap.set(id, { ...threat, coveredBy: [] });
      }
      coveredThreatMap.get(id).coveredBy.push(control?.name || threat.control_name || `Control ${controlId}`);
    });
  });

  const coveredThreats = Array.from(coveredThreatMap.values()).sort((a, b) => Number(b.weight) - Number(a.weight));
  const totalThreats = state.threats.length || 1;
  const coveragePct = Math.round((coveredThreats.length / totalThreats) * 100);

  const domainMap = coveredThreats.reduce((acc, threat) => {
    const domain = threat.category || "Uncategorized";
    if (!acc[domain]) acc[domain] = [];
    acc[domain].push(threat);
    return acc;
  }, {});

  const priorityCounts = coveredThreats.reduce((acc, threat) => {
    const priority = getPriority(Number(threat.weight));
    acc[priority] = (acc[priority] || 0) + 1;
    return acc;
  }, {});

  const controlContribution = selectedControls.map(control => {
    const controlId = Number(control.id);
    const threats = state.controlThreatMap[controlId] || [];
    const uniqueCovered = threats.filter(threat => coveredThreatMap.has(Number(threat.id))).length;
    return {
      id: controlId,
      name: control.name,
      covered: uniqueCovered,
      percent: Math.round((uniqueCovered / totalThreats) * 100),
    };
  }).sort((a, b) => b.covered - a.covered);

  const topDomains = Object.entries(domainMap)
    .map(([domain, threats]) => ({ domain, count: threats.length, percent: Math.round((threats.length / coveredThreats.length) * 100) || 0 }))
    .sort((a, b) => b.count - a.count);

  const topCriticalThreats = coveredThreats.slice(0, 6);
  const selectedControlNames = selectedControls.map(c => escapeHTML(c.name)).join(", ");

  coverageDetail.innerHTML = `
    <div class="control-dashboard-hero">
      <div>
        <span class="step-badge">Control Analysis Dashboard</span>
        <h3>${coveredThreats.length} of ${state.threats.length} threats covered</h3>
        <p>Selected controls: ${selectedControlNames}</p>
      </div>
      <div class="dashboard-donut" style="--value:${coveragePct * 3.6}deg">
        <div><strong>${coveragePct}%</strong><span>Total Coverage</span></div>
      </div>
    </div>

    <div class="control-kpi-grid">
      <div class="control-kpi-card">
        <i class="fa-solid fa-shield-halved"></i>
        <strong>${state.coverageSelectedControlIds.length}</strong>
        <span>Controls Selected</span>
      </div>
      <div class="control-kpi-card">
        <i class="fa-solid fa-triangle-exclamation"></i>
        <strong>${coveredThreats.length}</strong>
        <span>Threats Covered</span>
      </div>
      <div class="control-kpi-card">
        <i class="fa-solid fa-layer-group"></i>
        <strong>${Object.keys(domainMap).length}</strong>
        <span>Domains Covered</span>
      </div>
      <div class="control-kpi-card danger">
        <i class="fa-solid fa-fire"></i>
        <strong>${(priorityCounts.Critical || 0) + (priorityCounts.High || 0)}</strong>
        <span>Critical / High Threats</span>
      </div>
    </div>

    <div class="dashboard-two-column">
      <section class="dashboard-widget">
        <div class="widget-title-row">
          <div>
            <h3>Domain-wise Threat Coverage</h3>
            <p>Domains where the selected controls reduce risk exposure.</p>
          </div>
        </div>
        <div class="domain-dashboard-list">
          ${topDomains.map(item => `
            <div class="domain-dashboard-row">
              <div class="domain-row-head">
                <strong>${escapeHTML(item.domain)}</strong>
                <span>${item.count} threats · ${item.percent}%</span>
              </div>
              <div class="dashboard-bar"><span style="width:${Math.min(100, item.percent)}%"></span></div>
            </div>
          `).join("")}
        </div>
      </section>

      <section class="dashboard-widget">
        <div class="widget-title-row">
          <div>
            <h3>Selected Control Contribution</h3>
            <p>How much each selected control contributes to total coverage.</p>
          </div>
        </div>
        <div class="control-contribution-list">
          ${controlContribution.map(control => `
            <div class="control-contribution-row">
              <div>
                <strong>${escapeHTML(control.name)}</strong>
                <small>${control.covered} covered threats</small>
              </div>
              <div class="contribution-meter"><span style="width:${Math.min(100, control.percent)}%"></span></div>
              <b>${control.percent}%</b>
            </div>
          `).join("")}
        </div>
      </section>
    </div>

    <div class="dashboard-two-column">
      <section class="dashboard-widget">
        <div class="widget-title-row">
          <div>
            <h3>Priority Breakdown</h3>
            <p>Covered threats by risk severity.</p>
          </div>
        </div>
        <div class="priority-dashboard-grid">
          ${["Critical", "High", "Medium", "Low"].map(priority => {
            const count = priorityCounts[priority] || 0;
            const pct = Math.round((count / coveredThreats.length) * 100) || 0;
            return `
              <div class="priority-dashboard-card priority-card-${priority.toLowerCase()}">
                <span>${priority}</span>
                <strong>${count}</strong>
                <small>${pct}% of covered</small>
              </div>
            `;
          }).join("")}
        </div>
      </section>

      <section class="dashboard-widget">
        <div class="widget-title-row">
          <div>
            <h3>Top Covered Critical Threats</h3>
            <p>Highest-weight threats protected by selected controls.</p>
          </div>
        </div>
        <div class="critical-threat-list">
          ${topCriticalThreats.map(threat => {
            const priority = getPriority(Number(threat.weight));
            return `
              <div class="critical-threat-card">
                <div>
                  <strong>${escapeHTML(threat.name)}</strong>
                  <small>${escapeHTML(threat.category)} · Covered by ${escapeHTML(threat.coveredBy.join(", "))}</small>
                </div>
                <span class="priority-chip priority-${priority.toLowerCase()}">${priority}</span>
                <b>${Number(threat.weight).toFixed(2)}</b>
              </div>
            `;
          }).join("")}
        </div>
      </section>
    </div>

    <section class="dashboard-widget full-width-widget">
      <div class="widget-title-row">
        <div>
          <h3>Threats Covered by Domain</h3>
          <p>Compact domain grouped view of the threats protected by the selected controls.</p>
        </div>
      </div>
      <div class="domain-threat-grid">
        ${topDomains.map(item => {
          const threats = domainMap[item.domain].slice(0, 6);
          return `
            <details class="domain-threat-panel" open>
              <summary>
                <strong>${escapeHTML(item.domain)}</strong>
                <span>${item.count} threats</span>
              </summary>
              <div class="domain-threat-items">
                ${threats.map(threat => `
                  <div class="domain-threat-item">
                    <span>${escapeHTML(threat.name)}</span>
                    <small>${escapeHTML(threat.coveredBy.join(", "))}</small>
                  </div>
                `).join("")}
                ${domainMap[item.domain].length > 6 ? `<div class="more-domain-threats">+${domainMap[item.domain].length - 6} more threats in this domain</div>` : ""}
              </div>
            </details>
          `;
        }).join("")}
      </div>
    </section>
  `;
}


function buildAnalysisDashboard(result) {
  if (!analysisDashboardEl) return;
  const selectedThreats = state.selectedThreats || [];
  const selections = state.selections || [];
  const categories = selectedThreats.reduce((acc, threat) => {
    const category = threat.category || "Uncategorized";
    if (!acc[category]) acc[category] = { count: 0, totalWeight: 0 };
    acc[category].count += 1;
    acc[category].totalWeight += Number(threat.weight || 0);
    return acc;
  }, {});

  const categoryRows = Object.entries(categories)
    .sort((a, b) => b[1].count - a[1].count)
    .map(([category, data]) => ({
      category,
      count: data.count,
      avgWeight: data.count ? data.totalWeight / data.count : 0,
      pct: selectedThreats.length ? Math.round((data.count / selectedThreats.length) * 100) : 0,
    }));

  const avgWeight = selectedThreats.length
    ? selectedThreats.reduce((sum, t) => sum + Number(t.weight || 0), 0) / selectedThreats.length
    : 0;
  const avgEffectiveness = selections.length
    ? selections.reduce((sum, s) => sum + Number(s.effectiveness || 0), 0) / selections.length
    : 0;
  const uniqueControls = new Set(selections.map(s => Number(s.control_id))).size;
  const riskScore = Number(result?.risk_score || 0);
  const riskLevel = String(result?.risk_level || "LOW").toUpperCase();

  analysisDashboardEl.innerHTML = `
    <div class="dashboard-kpi-grid">
      <div class="dashboard-kpi"><span>Final Risk Score</span><strong>${riskScore.toFixed(3)}</strong><small>${riskLevel} risk posture</small></div>
      <div class="dashboard-kpi"><span>Threats Analyzed</span><strong>${selectedThreats.length}</strong><small>${categoryRows.length} categories selected</small></div>
      <div class="dashboard-kpi"><span>Controls Applied</span><strong>${uniqueControls}</strong><small>${selections.length} total selections</small></div>
      <div class="dashboard-kpi"><span>Avg Control Effectiveness</span><strong>${avgEffectiveness.toFixed(2)}</strong><small>Avg threat weight ${avgWeight.toFixed(2)}</small></div>
    </div>

    <div class="dashboard-grid">
      <div class="dashboard-card">
        <h3>Threats by Category</h3>
        <div class="bar-chart-list">
          ${categoryRows.map(row => `
            <div class="dashboard-bar-row">
              <strong>${escapeHTML(row.category)}</strong>
              <span class="dashboard-bar-track"><span class="dashboard-bar-fill" style="width:${Math.max(4, row.pct)}%"></span></span>
              <b>${row.count}</b>
            </div>
          `).join("") || `<p class="muted-note">No category data available.</p>`}
        </div>
      </div>

      <div class="dashboard-card">
        <h3>Control Effectiveness</h3>
        <div class="control-effectiveness-list">
          ${selections.slice(0, 8).map((s, index) => {
            const pct = Math.round(Number(s.effectiveness || 0) * 100);
            return `
              <div class="effectiveness-row">
                <strong>#${index + 1} ${escapeHTML(s.control_name || `Control ${s.control_id}`)}</strong>
                <span class="dashboard-bar-track"><span class="dashboard-bar-fill" style="width:${Math.max(4, pct)}%"></span></span>
                <b>${Number(s.effectiveness || 0).toFixed(2)}</b>
              </div>
            `;
          }).join("") || `<p class="muted-note">No control selections available.</p>`}
        </div>
      </div>
    </div>

    <div class="dashboard-card">
      <h3>Threat → Control Mapping</h3>
      <div class="dashboard-table">
        ${selections.map(selection => {
          const threat = selectedThreats.find(t => Number(t.id) === Number(selection.threat_id));
          const priority = getPriority(Number(threat?.weight || 0));
          return `
            <div class="dashboard-table-row">
              <strong>${escapeHTML(threat?.name || `Threat ${selection.threat_id}`)}</strong>
              <span>${escapeHTML(selection.control_name || `Control ${selection.control_id}`)}</span>
              <span class="priority-chip priority-${priority.toLowerCase()}">${priority}</span>
            </div>
          `;
        }).join("") || `<p class="muted-note">No mappings available.</p>`}
      </div>
    </div>
  `;
}

// --- Initialization ---

async function init() {
  try {
    state.threats = await fetchJSON("/threats");
    threatCountEl.textContent = state.threats.length;
    threatTotalCountEl.textContent = `of ${state.threats.length} threats`;
    
    // Populate Categories
    const categories = [...new Set(state.threats.map(t => t.category))].sort();
    categories.forEach(cat => {
      const opt = document.createElement("option");
      opt.value = cat;
      opt.textContent = cat;
      categoryFilterEl.appendChild(opt);
    });

    filterAndRenderThreats();
  } catch (err) {
    showToast("Backend connection failed", "error");
  }

  // Event Listeners
  startBtn.addEventListener("click", startAnalysis);
  threatSearchEl.addEventListener("input", filterAndRenderThreats);
  categoryFilterEl.addEventListener("change", filterAndRenderThreats);
  sortSelectEl.addEventListener("change", filterAndRenderThreats);
  
  clearSearchBtn.addEventListener("click", () => {
    threatSearchEl.value = "";
    filterAndRenderThreats();
  });

  if (resetFiltersBtn) {
    resetFiltersBtn.addEventListener("click", () => {
      threatSearchEl.value = "";
      categoryFilterEl.value = "";
      sortSelectEl.value = "priority-desc";
      filterAndRenderThreats();
    });
  }

  const globalSearch = document.getElementById("global-search");
  if (globalSearch) {
    globalSearch.addEventListener("input", () => {
      threatSearchEl.value = globalSearch.value;
      document.querySelectorAll(".nav-link").forEach(l => l.classList.toggle("active", l.dataset.tab === "analysis"));
      document.getElementById("tab-analysis").classList.remove("hidden");
      document.getElementById("tab-coverage").classList.add("hidden");
      filterAndRenderThreats();
    });
  }

  document.querySelectorAll(".nav-link[data-tab]").forEach(link => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const tab = link.dataset.tab;
      document.querySelectorAll(".nav-link[data-tab]").forEach(l => l.classList.toggle("active", l === link));
      document.getElementById("tab-analysis").classList.toggle("hidden", tab !== "analysis");
      document.getElementById("tab-coverage").classList.toggle("hidden", tab !== "coverage");
      if (tab === "coverage") renderCoverageOverview();
    });
  });

  const themeToggle = document.getElementById("theme-toggle");
  if (themeToggle) {
    themeToggle.addEventListener("click", () => {
      const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      themeToggle.innerHTML = next === "dark" ? '<i class="fas fa-moon"></i>' : '<i class="fas fa-sun"></i>';
    });
  }

  restartBtn.addEventListener("click", () => {
    state.selectedThreatIds = [];
    resultView.classList.add("hidden");
    if (analysisDashboardEl) analysisDashboardEl.innerHTML = "";
    selectionView.classList.remove("hidden");
    filterAndRenderThreats();
  });
}

document.addEventListener("DOMContentLoaded", init);
/* ------------------------------------------------------------------
   Compact UI override: replaces large threat/control card grids with
   searchable accordion lists and compact selectable rows.
------------------------------------------------------------------- */
function escapeHTML(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function getVisibleThreats() {
  const searchTerm = threatSearchEl.value.trim().toLowerCase();
  const selectedCategory = categoryFilterEl.value;
  const sortOption = sortSelectEl.value;

  let filtered = state.threats.filter((t) => {
    const name = String(t.name || "").toLowerCase();
    const category = String(t.category || "").toLowerCase();
    const matchesSearch = !searchTerm || name.includes(searchTerm) || category.includes(searchTerm);
    const matchesCategory = !selectedCategory || t.category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  if (sortOption === "priority-desc") filtered.sort((a, b) => b.weight - a.weight);
  else if (sortOption === "priority-asc") filtered.sort((a, b) => a.weight - b.weight);
  else if (sortOption === "name-asc") filtered.sort((a, b) => String(a.name).localeCompare(String(b.name)));
  else if (sortOption === "name-desc") filtered.sort((a, b) => String(b.name).localeCompare(String(a.name)));

  return filtered;
}

function filterAndRenderThreats() {
  const filtered = getVisibleThreats();
  const grouped = filtered.reduce((acc, t) => {
    acc[t.category] = acc[t.category] || [];
    acc[t.category].push(t);
    return acc;
  }, {});

  threatListEl.innerHTML = "";

  if (!filtered.length) {
    threatListEl.innerHTML = `
      <div class="empty-state-card">
        <i class="fa-solid fa-magnifying-glass"></i>
        <h3>No matching threats</h3>
        <p>Try another search term or reset the filters.</p>
      </div>
    `;
    updateSelectedCount();
    return;
  }

  const selectedVisible = filtered.filter(t => state.selectedThreatIds.includes(Number(t.id))).length;
  const summary = document.createElement("div");
  summary.className = "compact-selection-summary";
  const selectedThreats = state.threats.filter(t => state.selectedThreatIds.includes(Number(t.id)));
  summary.innerHTML = `
    <div>
      <h3>Compact threat picker</h3>
      <p>${selectedVisible} selected in current view · ${filtered.length} visible threats</p>
    </div>
    <div class="selected-chip-wrap">
      ${selectedThreats.length ? selectedThreats.slice(0, 8).map(t => `
        <button class="selected-chip" onclick="toggleThreat(${Number(t.id)}, false)" title="Remove ${escapeHTML(t.name)}">
          ${escapeHTML(t.name)} <i class="fa-solid fa-xmark"></i>
        </button>
      `).join("") : `<span class="muted-note">No threats selected yet</span>`}
      ${selectedThreats.length > 8 ? `<span class="more-chip">+${selectedThreats.length - 8} more</span>` : ""}
    </div>
  `;
  threatListEl.appendChild(summary);

  Object.keys(grouped).sort().forEach((category, categoryIndex) => {
    const group = grouped[category];
    const selectedInCategory = group.filter(t => state.selectedThreatIds.includes(Number(t.id))).length;
    const details = document.createElement("details");
    details.className = "threat-accordion";
    details.open = categoryIndex < 2 || selectedInCategory > 0 || Boolean(categoryFilterEl.value || threatSearchEl.value);
    details.innerHTML = `
      <summary class="threat-accordion-header">
        <div>
          <h3>${escapeHTML(category)}</h3>
          <span>${selectedInCategory} selected of ${group.length}</span>
        </div>
        <div class="category-actions" onclick="event.stopPropagation()">
          <button class="mini-action" onclick='bulkSelectCategoryVisible(${JSON.stringify(category)}, true)'>Select visible</button>
          <button class="mini-action muted" onclick='bulkSelectCategoryVisible(${JSON.stringify(category)}, false)'>Clear</button>
          <span class="threat-category-count">${group.length}</span>
        </div>
      </summary>
      <div class="compact-threat-list">
        ${group.map(threat => {
          const priority = getPriority(Number(threat.weight));
          const isChecked = state.selectedThreatIds.includes(Number(threat.id));
          return `
            <label class="compact-threat-row ${isChecked ? "selected" : ""}">
              <input type="checkbox" value="${Number(threat.id)}" ${isChecked ? "checked" : ""} onchange="toggleThreat(${Number(threat.id)}, this.checked)">
              <span class="row-main">
                <strong>${escapeHTML(threat.name)}</strong>
                <small>${escapeHTML(threat.category)}</small>
              </span>
              <span class="priority-chip priority-${priority.toLowerCase()}">${priority}</span>
              <span class="weight-badge">${Number(threat.weight).toFixed(2)}</span>
            </label>
          `;
        }).join("")}
      </div>
    `;
    threatListEl.appendChild(details);
  });

  updateSelectedCount();
}

window.bulkSelectCategoryVisible = (category, shouldSelect) => {
  const visible = getVisibleThreats().filter(t => t.category === category);
  visible.forEach(t => {
    const tid = Number(t.id);
    if (shouldSelect && !state.selectedThreatIds.includes(tid)) state.selectedThreatIds.push(tid);
    if (!shouldSelect) state.selectedThreatIds = state.selectedThreatIds.filter(id => id !== tid);
  });
  filterAndRenderThreats();
};

function renderControls(threat, controls) {
  controlListEl.innerHTML = `
    <div class="compact-control-panel">
      <div class="compact-control-note save-note">
        <i class="fa-solid fa-database"></i>
        Choose one recommended control. The selected threat, control, impact, probability and risk score will be saved in the database.
      </div>
      ${controls.map((c, idx) => {
        const probability = Number(threat.weight || 0);
        const impact = Number(c.impact || 0);
        const pairRisk = probability * impact;
        return `
          <div class="compact-control-row save-control-row" data-threat-id="${Number(threat.id)}" data-control-id="${Number(c.id)}">
            <span class="control-rank-pill">#${idx + 1}</span>
            <span class="row-main">
              <strong>${escapeHTML(c.name)}</strong>
              <small>${escapeHTML(c.impact_text || 'Standard mitigation control for this threat pattern.')}</small>
              <span class="pair-metrics">
                Probability: ${probability.toFixed(2)} · Impact: ${impact.toFixed(2)} · Risk: ${pairRisk.toFixed(3)}
              </span>
              <label class="replace-existing-check" onclick="event.stopPropagation()">
                <input type="checkbox" id="replace-${Number(threat.id)}-${Number(c.id)}" />
                Replace if already saved
              </label>
            </span>
            <span class="control-score">${Number(c.effectiveness).toFixed(2)}</span>
            <button
              class="mini-save-btn"
              data-threat-id="${Number(threat.id)}"
              data-control-id="${Number(c.id)}"
              data-control-name="${escapeHTML(c.name)}"
              data-effectiveness="${Number(c.effectiveness || 0)}"
              data-replace-id="replace-${Number(threat.id)}-${Number(c.id)}"
              onclick="selectControl(Number(this.dataset.threatId), Number(this.dataset.controlId), this.dataset.controlName, Number(this.dataset.effectiveness), document.getElementById(this.dataset.replaceId).checked)"
            >
              Save & Apply <i class="fa-solid fa-arrow-right"></i>
            </button>
          </div>
        `;
      }).join("")}
    </div>
  `;
}

window.setCoverageSearch = (value) => {
  state.coverageSearchTerm = value;
  renderCoverageOverview();
};

async function renderCoverageOverview() {
  if (!controlSelectorGrid) return;

  await loadCoverageData();

  if (!state.controls.length) {
    controlSelectorGrid.innerHTML = `
      <div class="empty-state-card">
        <i class="fa-solid fa-triangle-exclamation"></i>
        <h3>No controls found</h3>
        <p>Make sure your backend returns controls from /controls or /recommend-controls/{threat_id}.</p>
      </div>
    `;
    return;
  }

  const totalThreats = state.threats.length || 1;
  const term = String(state.coverageSearchTerm || "").toLowerCase();
  const filteredControls = state.controls.filter(control => String(control.name || "").toLowerCase().includes(term));

  controlSelectorGrid.innerHTML = `
    <div class="coverage-toolbar compact-toolbar">
      <div>
        <span class="step-badge">Control Selection</span>
        <h3>Compact control picker</h3>
        <p>Search and select one or multiple controls. Covered threats are combined automatically.</p>
      </div>
      <div class="coverage-toolbar-actions">
        <div class="inline-search">
          <i class="fas fa-search"></i>
          <input value="${escapeHTML(state.coverageSearchTerm || "")}" oninput="setCoverageSearch(this.value)" placeholder="Search controls..." />
        </div>
        <span class="count-pill" id="coverage-selected-count">${state.coverageSelectedControlIds.length} selected</span>
        <button class="btn btn-secondary" onclick="clearCoverageControls()">Clear</button>
      </div>
    </div>
    <div class="compact-control-list">
      ${filteredControls.map((control, index) => {
        const id = Number(control.id);
        const covered = state.controlThreatMap[id]?.length || 0;
        const pct = Math.round((covered / totalThreats) * 100);
        const selected = state.coverageSelectedControlIds.includes(id);
        return `
          <label class="coverage-control-row ${selected ? "selected" : ""}">
            <input type="checkbox" ${selected ? "checked" : ""} onchange="toggleCoverageControl(${id}, this.checked)">
            <span class="control-rank-pill">#${index + 1}</span>
            <span class="row-main">
              <strong>${escapeHTML(control.name)}</strong>
              <small>${covered} threats covered · ${pct}% total coverage</small>
            </span>
            <span class="coverage-mini-meter"><span style="width:${Math.min(100, pct)}%"></span></span>
            <span class="coverage-percent">${pct}%</span>
          </label>
        `;
      }).join("") || `
        <div class="empty-state-card">
          <i class="fa-solid fa-magnifying-glass"></i>
          <h3>No matching controls</h3>
          <p>Try another search term.</p>
        </div>
      `}
    </div>
  `;

  renderCoverageDetail();
}
