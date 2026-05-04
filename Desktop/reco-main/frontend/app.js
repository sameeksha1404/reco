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
  if (!res.ok) throw new Error(`Request failed: ${res.status}`);
  return res.json();
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
    btn.onclick = () => selectControl(threat.id, c.id);
    controlListEl.appendChild(btn);
  });
}

async function selectControl(threatId, controlId) {
  state.selections.push({ threat_id: threatId, control_id: controlId });
  state.currentIndex++;
  
  if (state.currentIndex < state.selectedThreats.length) {
    renderStep();
  } else {
    finishAnalysis();
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

  if (!state.coverageSelectedControlIds.length) {
    coverageDetail.classList.remove("hidden");
    coverageDetail.innerHTML = `
      <div class="coverage-empty">
        <i class="fa-solid fa-layer-group"></i>
        <h3>Select controls to view covered threats</h3>
        <p>You can select one control or combine multiple controls to see total threat coverage.</p>
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
  const coveragePct = state.threats.length ? Math.round((coveredThreats.length / state.threats.length) * 100) : 0;

  const categoryCounts = coveredThreats.reduce((acc, threat) => {
    acc[threat.category] = (acc[threat.category] || 0) + 1;
    return acc;
  }, {});

  coverageDetail.classList.remove("hidden");
  coverageDetail.innerHTML = `
    <div class="coverage-detail-header split">
      <div>
        <span class="step-badge">Threats Covered</span>
        <h3>${coveredThreats.length} of ${state.threats.length} threats covered</h3>
        <p>${selectedControls.length} selected control${selectedControls.length > 1 ? 's' : ''}: ${selectedControls.map(c => c.name).join(', ')}</p>
      </div>
      <div class="coverage-score-card">
        <strong>${coveragePct}%</strong>
        <span>Total Coverage</span>
      </div>
    </div>

    <div class="coverage-category-strip">
      ${Object.entries(categoryCounts).sort((a,b)=>b[1]-a[1]).map(([category, count]) => `
        <div class="category-coverage-chip">
          <strong>${count}</strong>
          <span>${category}</span>
        </div>
      `).join('')}
    </div>

    <div class="coverage-threat-list">
      ${coveredThreats.map(threat => {
        const priority = getPriority(Number(threat.weight));
        const pct = Math.round(Number(threat.weight) * 100);
        return `
          <div class="coverage-threat-row">
            <div>
              <strong>${threat.name}</strong>
              <span class="priority-chip priority-${priority.toLowerCase()}">${priority}</span>
              <small>Covered by: ${threat.coveredBy.join(', ')}</small>
            </div>
            <div class="row-bar"><span style="width:${Math.min(100, pct)}%"></span></div>
            <b>${Number(threat.weight).toFixed(2)}</b>
          </div>
        `;
      }).join('')}
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
    selectionView.classList.remove("hidden");
    filterAndRenderThreats();
  });
}

document.addEventListener("DOMContentLoaded", init);