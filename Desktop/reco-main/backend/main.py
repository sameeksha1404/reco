from csv import DictReader
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from recommender import HybridRecommendationEngine

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

app = FastAPI(title="Threat Recommendation Engine", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Pydantic models ───────────────────────────────────────────────────────────

class ThreatOut(BaseModel):
    id: int
    name: str
    category: str
    weight: float


class ControlOut(BaseModel):
    id: int
    name: str
    effectiveness: float


class ControlOption(BaseModel):
    id: int
    name: str
    effectiveness: float
    impact: float
    score: float
    impact_text: str


class ThreatCoverageItem(BaseModel):
    id: int
    name: str
    category: str
    weight: float
    mapping_impact: float
    score: float


class ControlCoverageResponse(BaseModel):
    control_id: int
    control_name: str
    effectiveness: float
    total_threats_covered: int
    covered_threats: list[ThreatCoverageItem]
    category_breakdown: dict[str, int]
    avg_mapping_impact: float


class SelectionItem(BaseModel):
    threat_id: int = Field(..., gt=0)
    control_id: int = Field(..., gt=0)


class FinalRiskRequest(BaseModel):
    selections: list[SelectionItem]


class FinalRiskResponse(BaseModel):
    risk_score: float
    risk_level: str


# ── Data loading ──────────────────────────────────────────────────────────────

def load_csv(file_name: str) -> list[dict]:
    with open(DATA_DIR / file_name, newline="", encoding="utf-8") as file:
        rows = [dict(row) for row in DictReader(file)]

    for row in rows:
        if "threat_id" in row and "id" not in row:
            row["id"] = row["threat_id"]
        if "control_id" in row and "id" not in row:
            row["id"] = row["control_id"]
        if "threat_name" in row and "name" not in row:
            row["name"] = row["threat_name"]
        if "control_name" in row and "name" not in row:
            row["name"] = row["control_name"]
    return rows


def _get_int(item: dict, *keys: str, default: int = 0) -> int:
    for key in keys:
        value = item.get(key)
        if value not in (None, ""):
            return int(value)
    return default


def _get_float(item: dict, *keys: str, default: float = 0.0) -> float:
    for key in keys:
        value = item.get(key)
        if value not in (None, ""):
            return float(value)
    return default


THREATS = load_csv("threats.csv")
CONTROLS = load_csv("controls.csv")
THREAT_MAP = load_csv("threat_control_map.csv")

THREAT_BY_ID: dict[int, dict] = {
    _get_int(item, "id", "threat_id"): {
        "id": _get_int(item, "id", "threat_id"),
        "name": item.get("name", item.get("threat_name", "")),
        "category": item.get("category", ""),
        "weight": _get_float(item, "weight", default=0.5),
    }
    for item in THREATS
}

CONTROL_BY_ID: dict[int, dict] = {
    _get_int(item, "id", "control_id"): {
        "id": _get_int(item, "id", "control_id"),
        "name": item.get("name", item.get("control_name", "")),
        "effectiveness": _get_float(item, "effectiveness", default=0.5),
    }
    for item in CONTROLS
}

for row in THREAT_MAP:
    if "effectiveness" not in row or row["effectiveness"] == "":
        control_id = _get_int(row, "control_id")
        row["effectiveness"] = str(CONTROL_BY_ID.get(control_id, {}).get("effectiveness", 0.5))
    if "mapping_impact" not in row or row["mapping_impact"] == "":
        row["mapping_impact"] = "0.5"

# Keep reverse index for the coverage dashboard (unchanged)
MAP_BY_CONTROL: dict[int, list[dict]] = {}
PAIR_IMPACT: dict[tuple[int, int], float] = {}

for row in THREAT_MAP:
    threat_id = _get_int(row, "threat_id")
    control_id = _get_int(row, "control_id")
    if threat_id == 0 or control_id == 0:
        continue

    raw_effectiveness = row.get("effectiveness")
    if raw_effectiveness not in (None, ""):
        effectiveness = float(raw_effectiveness)
    else:
        effectiveness = CONTROL_BY_ID.get(control_id, {}).get("effectiveness", 0.5)

    impact = _get_float(row, "mapping_impact", default=0.5)
    score = round(effectiveness * impact, 4)

    PAIR_IMPACT[(threat_id, control_id)] = impact

    threat_info = THREAT_BY_ID.get(threat_id, {})
    rev_item = {
        "id": threat_id,
        "name": threat_info.get("name", ""),
        "category": threat_info.get("category", ""),
        "weight": threat_info.get("weight", 0.0),
        "mapping_impact": impact,
        "score": score,
    }
    MAP_BY_CONTROL.setdefault(control_id, []).append(rev_item)

# Sort threats per control by mapping_impact desc (coverage dashboard)
for control_id, items in MAP_BY_CONTROL.items():
    MAP_BY_CONTROL[control_id] = sorted(items, key=lambda x: (-x["mapping_impact"], x["name"]))

# ── Boot the recommendation engine ───────────────────────────────────────────
#
#  alpha = 0.50  →  50% collaborative filtering (SVD latent factors)
#  beta  = 0.20  →  20% original domain base score
#  cb    = 0.30  →  30% content-based cosine similarity (derived from 1-alpha-beta)
#
ENGINE = HybridRecommendationEngine(n_factors=8, alpha=0.50, beta=0.20)
ENGINE.fit(THREAT_BY_ID, CONTROL_BY_ID, THREAT_MAP)


# ── Impact text helper ────────────────────────────────────────────────────────

_IMPACT_DESCRIPTIONS: dict[str, dict[str, str]] = {
    "Multi-Factor Authentication": {
        "high":   "Blocks account takeover by requiring a second factor — attackers with stolen credentials hit a hard wall.",
        "medium": "Adds meaningful friction to login-based attacks; partial effectiveness without phishing-resistant factors.",
        "low":    "Provides limited uplift here; MFA is not the primary attack vector for this threat.",
    },
    "Endpoint Detection and Response": {
        "high":   "Detects and contains malicious processes in real time — critical for threats that execute on the host.",
        "medium": "Catches most known patterns; advanced fileless or obfuscated variants may evade detection briefly.",
        "low":    "Endpoint visibility helps as a secondary signal but does not directly neutralise this attack vector.",
    },
    "Network Segmentation": {
        "high":   "Limits blast radius by isolating infected segments, effectively stopping lateral spread.",
        "medium": "Slows attacker movement across subnets; full effectiveness requires micro-segmentation.",
        "low":    "Segmentation is not the primary mitigant here; the threat operates above the network layer.",
    },
    "Least Privilege Access": {
        "high":   "Removes excess permissions that attackers rely on; dramatically reduces the damage of a compromised account.",
        "medium": "Reduces exploitable permissions but may still leave service accounts with elevated rights.",
        "low":    "Privilege controls offer marginal gain against this threat, which does not depend on permission abuse.",
    },
    "Security Awareness Training": {
        "high":   "Human recognition is the first and most cost-effective defence for socially engineered attacks.",
        "medium": "Reduces click rates but cannot eliminate human error; technical controls must back it up.",
        "low":    "Training has minimal bearing on a technical exploit that does not involve human action.",
    },
    "Patch Management": {
        "high":   "Eliminates the known vulnerability that the attack exploits — the most direct remediation available.",
        "medium": "Closes most exposure; zero-day variants or mispatched systems may still be exploitable.",
        "low":    "Patching helps general hygiene but this threat does not rely on unpatched software.",
    },
    "Email Filtering": {
        "high":   "Stops malicious payloads and phishing links before they reach the inbox — primary prevention layer.",
        "medium": "Catches the majority of commodity phishing; targeted spear-phishing may still slip through.",
        "low":    "Email is not the delivery mechanism for this threat; filtering provides no direct mitigation.",
    },
    "Data Encryption": {
        "high":   "Renders exfiltrated data unreadable — even a successful breach yields no usable intelligence.",
        "medium": "Protects data at rest; in-transit or in-memory exposure may still be exploitable.",
        "low":    "Encryption does not address the attack vector; the threat targets access, not data confidentiality.",
    },
    "Web Application Firewall": {
        "high":   "Intercepts and drops malicious HTTP payloads at the perimeter before they reach application logic.",
        "medium": "Blocks common attack signatures; custom or obfuscated payloads may bypass rule sets.",
        "low":    "The WAF is not in the threat's attack path; mitigation must come from a different control layer.",
    },
    "Backup and Recovery": {
        "high":   "Guarantees business continuity — data can be restored quickly, removing the attacker's leverage.",
        "medium": "Reduces recovery time but backup integrity and frequency determine actual effectiveness.",
        "low":    "Recovery capabilities do not prevent this threat from materialising or causing initial harm.",
    },
    "SIEM Monitoring": {
        "high":   "Correlates signals across systems to detect and alert on attack patterns in near real time.",
        "medium": "Provides valuable telemetry; detection quality depends on tuned rules and analyst response time.",
        "low":    "Monitoring improves visibility but does not prevent the threat from executing.",
    },
    "DLP Policy Enforcement": {
        "high":   "Blocks unauthorized data movement at the policy boundary — direct prevention of exfiltration.",
        "medium": "Catches common channels (email, USB); encrypted or covert channels may evade DLP rules.",
        "low":    "Data loss prevention is tangential here; the threat does not target data movement.",
    },
    "Vulnerability Scanning": {
        "high":   "Identifies exploitable weaknesses before attackers do — enabling proactive remediation.",
        "medium": "Finds known CVEs reliably; logic flaws and zero-days fall outside scanner coverage.",
        "low":    "Scanning provides background hygiene but does not directly address this threat vector.",
    },
    "Zero Trust Policy": {
        "high":   "Enforces continuous verification — no implicit trust means attackers gain no foothold from a single compromise.",
        "medium": "Strong lateral movement prevention; full value requires consistent policy enforcement across all resources.",
        "low":    "Zero-trust principles are beneficial broadly but offer limited direct mitigation for this specific threat.",
    },
    "Incident Response Playbooks": {
        "high":   "Enables a rapid, coordinated response — minimises dwell time and business impact when a breach occurs.",
        "medium": "Improves response speed; effectiveness depends on playbook accuracy and team readiness.",
        "low":    "Response procedures help after the fact but do not prevent this threat from succeeding.",
    },
}

_DEFAULT_IMPACT = {
    "high":   "This control provides strong, direct mitigation against the threat's primary attack vector.",
    "medium": "This control reduces exposure but should be paired with complementary controls for full coverage.",
    "low":    "This control offers limited direct mitigation; consider higher-impact alternatives for this threat.",
}


def get_impact_text(control_name: str, score: float) -> str:
    bucket = "high" if score >= 0.72 else ("medium" if score >= 0.55 else "low")
    descriptions = _IMPACT_DESCRIPTIONS.get(control_name, _DEFAULT_IMPACT)
    return descriptions[bucket]


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "engine": "hybrid-svd-cf+cb+ml", "version": "3.0.0"}


@app.get("/threats", response_model=list[ThreatOut])
async def get_threats():
    return sorted(THREAT_BY_ID.values(), key=lambda item: (item["category"], item["name"]))


@app.get("/controls", response_model=list[ControlOut])
async def get_all_controls():
    return sorted(CONTROL_BY_ID.values(), key=lambda c: c["name"])


@app.get("/recommend-controls/{threat_id}", response_model=list[ControlOption])
async def recommend_controls(threat_id: int):
    """
    Recommend top 3 controls using the Hybrid SVD + Content-Based + ML engine.

    The engine blends four signals:
      - Collaborative filtering (SVD latent factors) — 45%
      - Content-based cosine similarity — 20%
      - Supervised ML score — 15%
      - Original domain base score — 20%
    """
    if threat_id not in THREAT_BY_ID:
        raise HTTPException(status_code=404, detail="Threat not found")

    recommendations = ENGINE.recommend(threat_id, top_k=3)

    result = []
    for rec in recommendations:
        cid = rec["control_id"]
        control = CONTROL_BY_ID.get(cid)
        if not control:
            continue

        # Use the engine's final_score as the display score
        # Use impact from known pair if it exists, otherwise engine's estimate
        impact = PAIR_IMPACT.get((threat_id, cid), rec["impact"])
        score = rec["final_score"]

        result.append({
            "id": cid,
            "name": control["name"],
            "effectiveness": control["effectiveness"],
            "impact": impact,
            "score": score,
            "impact_text": get_impact_text(control["name"], score),
        })

    return result


@app.get("/controls/{threat_id}", response_model=list[ControlOption])
async def get_controls(threat_id: int):
    """Alias for recommend-controls."""
    return await recommend_controls(threat_id)


@app.get("/recommend-explain/{threat_id}/{control_id}")
async def explain_recommendation(threat_id: int, control_id: int):
    """
    Expose the engine's signal breakdown for a specific (threat, control) pair.
    Shows exactly how much each signal contributed to the recommendation.
    """
    if threat_id not in THREAT_BY_ID:
        raise HTTPException(status_code=404, detail="Threat not found")
    if control_id not in CONTROL_BY_ID:
        raise HTTPException(status_code=404, detail="Control not found")

    explanation = ENGINE.explain(threat_id, control_id)
    similar = ENGINE.similar_threats(threat_id, top_k=3)

    similar_named = [
        {"threat_id": tid, "name": THREAT_BY_ID[tid]["name"], "similarity": sim}
        for tid, sim in similar
        if tid in THREAT_BY_ID
    ]

    return {
        "threat": THREAT_BY_ID[threat_id]["name"],
        "control": CONTROL_BY_ID[control_id]["name"],
        "signal_breakdown": explanation,
        "similar_threats": similar_named,
        "note": (
            "CF signal captures latent patterns shared with similar threats. "
            "CB signal measures semantic feature overlap between threat and control names/categories."
        ),
    }


@app.get("/control-coverage/{control_id}", response_model=ControlCoverageResponse)
async def get_control_coverage(control_id: int):
    """Get all threats covered by a control + stats. (Unchanged — uses raw data)"""
    if control_id not in CONTROL_BY_ID:
        raise HTTPException(status_code=404, detail="Control not found")

    control = CONTROL_BY_ID[control_id]
    threats = MAP_BY_CONTROL.get(control_id, [])

    category_breakdown: dict[str, int] = {}
    total_impact = 0.0
    for t in threats:
        category_breakdown[t["category"]] = category_breakdown.get(t["category"], 0) + 1
        total_impact += t["mapping_impact"]

    avg_impact = round(total_impact / len(threats), 4) if threats else 0.0

    return {
        "control_id": control_id,
        "control_name": control["name"],
        "effectiveness": control["effectiveness"],
        "total_threats_covered": len(threats),
        "covered_threats": threats,
        "category_breakdown": category_breakdown,
        "avg_mapping_impact": avg_impact,
    }


@app.post("/final-risk", response_model=FinalRiskResponse)
async def final_risk(payload: FinalRiskRequest):
    if not payload.selections:
        raise HTTPException(status_code=400, detail="At least one selection is required")

    probabilities = []
    impacts = []

    for item in payload.selections:
        threat = THREAT_BY_ID.get(item.threat_id)
        if not threat:
            raise HTTPException(status_code=404, detail=f"Threat {item.threat_id} not found")

        if item.control_id not in CONTROL_BY_ID:
            raise HTTPException(status_code=404, detail=f"Control {item.control_id} not found")

        # Use known pair impact if available, else fall back to engine estimate
        pair = (item.threat_id, item.control_id)
        if pair in PAIR_IMPACT:
            impact_val = PAIR_IMPACT[pair]
        else:
            # Engine provides an estimated impact for novel pairs
            recs = ENGINE.recommend(item.threat_id, top_k=len(CONTROL_BY_ID))
            rec_map = {r["control_id"]: r["impact"] for r in recs}
            impact_val = rec_map.get(item.control_id, 0.5)

        probabilities.append(threat["weight"])
        impacts.append(impact_val)

    probability = sum(probabilities) / len(probabilities)
    impact = sum(impacts) / len(impacts)
    risk_score = round(probability * impact, 4)

    if risk_score < 0.33:
        level = "Low"
    elif risk_score < 0.66:
        level = "Medium"
    else:
        level = "High"

    return FinalRiskResponse(risk_score=risk_score, risk_level=level)
