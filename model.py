"""
Risk prediction module.

The website only ever calls `predict(record)`. Today that uses a transparent
placeholder formula (likelihood x impact). When the trained XGBoost model is
ready, save it as models/xgb_model.joblib and implement `encode_features()`
below - the website does not need any other change.

A "record" is a dict with the keys listed in FIELDS (same names as the CSV
columns). See README.md for the full contract.
"""

from __future__ import annotations

import math
import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Allowed values. The XGBoost training data MUST use exactly these spellings.
# ---------------------------------------------------------------------------
OPTIONS = {
    "business_type": ["University", "Hospital", "Bank", "E-commerce",
                      "Government", "Telecommunication", "Other"],
    "system_criticality": ["Low", "Medium", "High", "Critical"],
    "data_sensitivity": ["Public", "Internal", "Confidential", "Highly Sensitive"],
    "exposure_level": ["Internal Only", "Employee Access", "Registered Users",
                       "Public Internet-Facing"],
    "business_impact": ["Low", "Medium", "High", "Critical"],
    "connected_system_criticality": ["None", "Low", "Medium", "High", "Critical"],
    "attack_vector": ["Network", "Adjacent", "Local", "Physical"],
    "attack_complexity": ["Low", "High"],
    "privileges_required": ["None", "Low", "High"],
    "user_interaction": ["No", "Yes"],
    "exploit_available": ["No", "Yes"],
    "known_exploited": ["No", "Yes"],
    "patch_available": ["No", "Yes"],
}

RELATED_ASSETS = [
    "Students", "Employees", "Customers", "Financial Records", "Medical Records",
    "Grades Database", "Authentication System", "Payment System", "Servers",
    "Databases", "APIs", "Network Devices", "Reputation", "Business Operations",
]
SENSITIVE_ASSETS = {"Financial Records", "Medical Records", "Payment System",
                    "Authentication System"}

# Numeric fields: (min, max)
NUMBERS = {
    "cvss_score": (0.0, 10.0),
    "vulnerability_age_days": (0, 10000),
    "affected_users": (0, 10_000_000),
    "connected_systems": (0, 100),
}

# Free-text notes: shown to the user, NOT used by the model.
NOTES = ["system_name", "system_purpose", "impact_description"]

FIELDS = (["cve_id"] + list(NUMBERS) + list(OPTIONS) + ["related_assets"] + NOTES)

RISK_LEVELS = ["Low", "Medium", "High", "Critical"]
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Validation (used for both the form and CSV rows)
# ---------------------------------------------------------------------------
def validate(raw: dict) -> tuple[dict, list[str]]:
    """Clean one input row. Returns (record, errors)."""
    errors: list[str] = []
    rec: dict = {}

    cve = str(raw.get("cve_id", "") or "").strip().upper()
    if not CVE_PATTERN.match(cve):
        errors.append(f"cve_id '{cve or '(empty)'}' must look like CVE-2024-12345")
    rec["cve_id"] = cve

    for field, (lo, hi) in NUMBERS.items():
        value = raw.get(field)
        try:
            num = float(value)
            if math.isnan(num):
                raise ValueError
        except (TypeError, ValueError):
            errors.append(f"{field} must be a number")
            num = lo
        if not lo <= num <= hi:
            errors.append(f"{field} must be between {lo} and {hi}")
        rec[field] = round(num, 1) if field == "cvss_score" else int(num)

    for field, allowed in OPTIONS.items():
        value = str(raw.get(field, "") or "").strip()
        match = next((a for a in allowed if a.lower() == value.lower()), None)
        if match is None:
            errors.append(f"{field} '{value}' must be one of: {', '.join(allowed)}")
            match = allowed[0]
        rec[field] = match

    assets = raw.get("related_assets", [])
    if isinstance(assets, str):
        assets = [a.strip() for a in assets.split(";") if a.strip()]
    lookup = {a.lower(): a for a in RELATED_ASSETS}
    clean_assets = []
    for a in assets:
        if str(a).lower() in lookup:
            clean_assets.append(lookup[str(a).lower()])
        else:
            errors.append(f"related asset '{a}' is not in the allowed list")
    rec["related_assets"] = clean_assets

    for field in NOTES:
        value = raw.get(field, "")
        rec[field] = "" if value is None or (isinstance(value, float) and math.isnan(value)) \
            else str(value).strip()[:500]

    return rec, errors


# ---------------------------------------------------------------------------
# Placeholder scoring: likelihood x impact, with an explanation of each factor
# ---------------------------------------------------------------------------
_LIKELIHOOD_MAX = 30 + 10 + 12 + 5 + 6 + 3 + 4 + 2 + 2
_IMPACT_MAX = 15 + 10 + 9 + 10 + 12 + 7 + 3 + 6 + 3


def _placeholder_scores(r: dict) -> tuple[float, list[tuple[str, float]]]:
    like: list[tuple[str, float]] = [
        (f"CVSS score {r['cvss_score']}", r["cvss_score"] * 3),
        ("Public exploit available", 10 if r["exploit_available"] == "Yes" else 0),
        ("Known exploited (CISA KEV)", 12 if r["known_exploited"] == "Yes" else 0),
        ("No patch available", 5 if r["patch_available"] == "No" else 0),
        (f"Attack vector: {r['attack_vector']}",
         {"Network": 6, "Adjacent": 3, "Local": 1, "Physical": 0}[r["attack_vector"]]),
        ("Low attack complexity", 3 if r["attack_complexity"] == "Low" else 0),
        (f"Privileges required: {r['privileges_required']}",
         {"None": 4, "Low": 2, "High": 0}[r["privileges_required"]]),
        ("No user interaction needed", 2 if r["user_interaction"] == "No" else 0),
        ("Vulnerability older than 180 days", 2 if r["vulnerability_age_days"] > 180 else 0),
    ]
    users = r["affected_users"]
    sensitive = SENSITIVE_ASSETS.intersection(r["related_assets"])
    conn = r["connected_systems"]
    imp: list[tuple[str, float]] = [
        (f"{r['system_criticality']} system criticality",
         {"Low": 0, "Medium": 5, "High": 10, "Critical": 15}[r["system_criticality"]]),
        (f"{r['data_sensitivity']} data",
         {"Public": 0, "Internal": 3, "Confidential": 7, "Highly Sensitive": 10}[r["data_sensitivity"]]),
        (f"Exposure: {r['exposure_level']}",
         {"Internal Only": 0, "Employee Access": 2, "Registered Users": 5,
          "Public Internet-Facing": 9}[r["exposure_level"]]),
        (f"{users:,} affected users",
         10 if users > 100_000 else 8 if users > 10_000 else 5 if users > 1_000 else 2 if users > 100 else 0),
        (f"{r['business_impact']} business impact",
         {"Low": 0, "Medium": 4, "High": 8, "Critical": 12}[r["business_impact"]]),
        (f"Connected systems are {r['connected_system_criticality'].lower()} criticality",
         {"None": 0, "Low": 1, "Medium": 3, "High": 5, "Critical": 7}[r["connected_system_criticality"]]),
        (f"{conn} connected systems", 3 if conn >= 10 else 2 if conn >= 3 else 1 if conn >= 1 else 0),
        ("Sensitive assets: " + ", ".join(sorted(sensitive)) if sensitive else "Sensitive assets",
         min(6, 2 * len(sensitive))),
        (f"Business type: {r['business_type']}",
         3 if r["business_type"] in ("Hospital", "Bank", "Government")
         else 2 if r["business_type"] in ("Telecommunication", "E-commerce") else 0),
    ]
    L = sum(v for _, v in like) / _LIKELIHOOD_MAX
    I = sum(v for _, v in imp) / _IMPACT_MAX
    # Blend of the geometric mean (likelihood x impact) and each part alone,
    # so a severe bug on an unimportant system is not scored as zero.
    score = 100 * (0.5 * math.sqrt(L * I) + 0.25 * L + 0.25 * I)
    factors = [(name, pts) for name, pts in like + imp if pts > 0]
    factors.sort(key=lambda f: f[1], reverse=True)
    return score, factors


def level_for(score: float) -> str:
    if score >= 75:
        return "Critical"
    if score >= 55:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def recommendation(r: dict, level: str) -> str:
    base = {
        "Critical": "Remediate immediately (within 24-48 hours) and notify the system owner.",
        "High": "Remediate within 7 days and monitor the system closely until fixed.",
        "Medium": "Schedule remediation in the next patch cycle (within 30 days).",
        "Low": "Track and fix during routine maintenance.",
    }[level]
    extra = []
    if r["known_exploited"] == "Yes":
        extra.append("It is in the CISA KEV catalog, so treat it as actively exploited.")
    if r["patch_available"] == "Yes":
        extra.append("A vendor patch is available - apply it.")
    else:
        extra.append("No patch exists yet: apply compensating controls "
                     "(WAF rules, disable the vulnerable feature, or isolate the system).")
    if r["exposure_level"] == "Public Internet-Facing" and level in ("Critical", "High"):
        extra.append("Restrict internet access to this system until it is fixed.")
    if r["connected_system_criticality"] in ("High", "Critical"):
        extra.append("Review connected systems for lateral-movement risk.")
    return " ".join([base] + extra)


# ---------------------------------------------------------------------------
# Real model hook (for the XGBoost model)
# ---------------------------------------------------------------------------
MODEL_PATH = Path(__file__).parent / "models" / "xgb_model.joblib"
_model = None
_model_error: str | None = None


def encode_features(r: dict) -> list[float]:
    """
    TODO (model team): turn a validated record into the exact feature vector
    the XGBoost model was trained on, in the same column order.
    Must match the preprocessing used during training.
    """
    raise NotImplementedError("encode_features() has not been written yet")


def _load_model():
    global _model, _model_error
    if _model is not None or _model_error is not None or not MODEL_PATH.exists():
        return _model
    try:
        import joblib  # only needed once the real model exists
        _model = joblib.load(MODEL_PATH)
    except Exception as exc:  # keep the site working if loading fails
        _model_error = str(exc)
    return _model


def model_status() -> str:
    """'xgboost' when the trained model is in use, otherwise 'demo'."""
    model = _load_model()
    if model is None:
        return "demo"
    try:
        encode_features(_example_record())
        return "xgboost"
    except Exception:
        return "demo"


def _example_record() -> dict:
    rec, _ = validate({
        "cve_id": "CVE-2024-0001", "cvss_score": 5, "vulnerability_age_days": 1,
        "affected_users": 1, "connected_systems": 0,
        **{k: v[0] for k, v in OPTIONS.items()},
    })
    return rec


# ---------------------------------------------------------------------------
# The one function the website calls
# ---------------------------------------------------------------------------
def predict(record: dict) -> dict:
    """
    Input:  a validated record (see validate()).
    Output: {risk_level, risk_score (0-100), top_factors [(name, points)],
             recommendation, source ('demo' or 'xgboost')}
    """
    score, factors = _placeholder_scores(record)
    level = level_for(score)
    source = "demo"

    model = _load_model()
    if model is not None:
        try:
            x = [encode_features(record)]
            probs = model.predict_proba(x)[0]            # classes: Low, Medium, High, Critical
            idx = max(range(len(probs)), key=lambda i: probs[i])
            level = RISK_LEVELS[idx]
            score = 100 * sum(p * i for i, p in enumerate(probs)) / (len(probs) - 1)
            source = "xgboost"
        except Exception:
            pass  # fall back to demo scoring

    return {
        "risk_level": level,
        "risk_score": round(score, 1),
        "top_factors": factors[:5],
        "recommendation": recommendation(record, level),
        "source": source,
    }
