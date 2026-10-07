"""
MITRE ATT&CK mapping engine.

Loads technique/tactic data from the local JSON file, scores each technique
against the alert text, and returns ranked mappings with explanations.
"""
import json
import re
from pathlib import Path
from typing import Optional

# ── Load data once at import time ─────────────────────────────────────────────

_DATA_PATH = Path(__file__).parent.parent / "data" / "mitre_data.json"

with open(_DATA_PATH, "r") as _f:
    _MITRE_DATA: dict = json.load(_f)

TACTICS: list[dict] = _MITRE_DATA["tactics"]
TECHNIQUES: list[dict] = _MITRE_DATA["techniques"]

# Build a flat list of (technique_dict, is_sub, parent_id) tuples
_ALL_TECHNIQUES: list[tuple[dict, bool, Optional[str]]] = []
for _tech in TECHNIQUES:
    _ALL_TECHNIQUES.append((_tech, False, None))
    for _sub in _tech.get("sub_techniques", []):
        _ALL_TECHNIQUES.append((_sub, True, _tech["id"]))

# Map tactic id → tactic dict
TACTIC_MAP: dict[str, dict] = {t["id"]: t for t in TACTICS}

# Map technique id → (technique_dict, is_sub, parent_id)
TECHNIQUE_MAP: dict[str, tuple] = {t[0]["id"]: t for t in _ALL_TECHNIQUES}

# Map technique id → parent technique's tactic info
def _get_tactic_info(tech_dict: dict, is_sub: bool, parent_id: Optional[str]) -> tuple[str, str]:
    """Return (tactic_id, tactic_name) for a technique."""
    if not is_sub:
        tids = tech_dict.get("tactic_ids", [])
        tnames = tech_dict.get("tactic_names", [])
        return (tids[0] if tids else ""), (tnames[0] if tnames else "")
    # sub-technique: inherit from parent
    if parent_id and parent_id in TECHNIQUE_MAP:
        parent = TECHNIQUE_MAP[parent_id][0]
        tids = parent.get("tactic_ids", [])
        tnames = parent.get("tactic_names", [])
        return (tids[0] if tids else ""), (tnames[0] if tnames else "")
    return "", ""


# ── Scoring ───────────────────────────────────────────────────────────────────

def _score_technique(text_lower: str, tech: dict) -> tuple[float, list[str]]:
    """
    Score a technique against alert text.
    Returns (raw_score 0-1, matched_keywords list).
    """
    keywords: list[str] = tech.get("keywords", [])
    if not keywords:
        return 0.0, []

    matched = [kw for kw in keywords if kw.lower() in text_lower]
    if not matched:
        return 0.0, []

    # Weight: proportion of keywords matched, but bonus for > 1 match
    ratio = len(matched) / len(keywords)
    bonus = min(0.3, (len(matched) - 1) * 0.1)
    score = min(1.0, ratio + bonus)
    return score, matched


def _confidence_label(score: float, matched_count: int) -> str:
    if score >= 0.5 or matched_count >= 3:
        return "High"
    if score >= 0.25 or matched_count >= 2:
        return "Medium"
    return "Low"


def _build_explanation(
    alert_text: str,
    tech: dict,
    matched_keywords: list[str],
    confidence: str,
    is_sub: bool,
    parent_id: Optional[str],
) -> str:
    name = tech["name"]
    tid = tech["id"]
    kw_str = ", ".join(f'"{k}"' for k in matched_keywords[:5])

    parts = [
        f"This alert was mapped to **{tid} – {name}** with **{confidence}** confidence.",
        f"The following indicator(s) found in the alert triggered this match: {kw_str}.",
    ]

    if is_sub and parent_id:
        parent_name = TECHNIQUE_MAP[parent_id][0]["name"] if parent_id in TECHNIQUE_MAP else parent_id
        parts.append(
            f"This is a sub-technique of {parent_id} ({parent_name}), providing a more specific classification."
        )

    desc = tech.get("description", "")
    if desc:
        parts.append(desc)

    return " ".join(parts)


def _build_indicators_found(
    alert_text: str,
    matched_keywords: list[str],
    parsed: dict,
) -> list[str]:
    """Compile a human-readable list of indicators found in the alert."""
    indicators: list[str] = []

    for kw in matched_keywords[:8]:
        indicators.append(f'Keyword matched: "{kw}"')

    if parsed.get("username"):
        indicators.append(f"Username identified: {parsed['username']}")
    if parsed.get("source_ip"):
        indicators.append(f"Source IP: {parsed['source_ip']}")
    if parsed.get("destination_ip"):
        indicators.append(f"Destination IP: {parsed['destination_ip']}")
    if parsed.get("process_name"):
        indicators.append(f"Process name: {parsed['process_name']}")
    if parsed.get("command_line"):
        cmd = parsed["command_line"][:80]
        indicators.append(f"Command line fragment: {cmd}{'...' if len(parsed['command_line']) > 80 else ''}")
    if parsed.get("file_name"):
        indicators.append(f"File name: {parsed['file_name']}")
    if parsed.get("hostname"):
        indicators.append(f"Hostname: {parsed['hostname']}")

    return indicators


# ── Public API ────────────────────────────────────────────────────────────────

def map_alert(raw_text: str, parsed: dict, max_results: int = 5) -> list[dict]:
    """
    Map an alert to MITRE ATT&CK techniques.

    Returns a list of mapping dicts (sorted by confidence_score desc), each
    containing all fields needed to populate the DB model.
    """
    text_lower = raw_text.lower()
    results: list[dict] = []

    # Score every technique and sub-technique
    seen_parent: set[str] = set()

    for tech, is_sub, parent_id in _ALL_TECHNIQUES:
        score, matched = _score_technique(text_lower, tech)
        if score <= 0.0:
            continue

        # Prefer sub-techniques over parents when both match
        if is_sub and parent_id in seen_parent:
            # Remove the parent entry from results (sub is more specific)
            results = [r for r in results if r["technique_id"] != parent_id]
        if not is_sub:
            seen_parent.add(tech["id"])

        tactic_id, tactic_name = _get_tactic_info(tech, is_sub, parent_id)
        confidence = _confidence_label(score, len(matched))
        explanation = _build_explanation(raw_text, tech, matched, confidence, is_sub, parent_id)
        indicators = _build_indicators_found(raw_text, matched, parsed)

        # Prefer sub-technique investigation steps; fall back to parent
        inv_steps = tech.get("investigation_steps", [])
        if not inv_steps and is_sub and parent_id and parent_id in TECHNIQUE_MAP:
            inv_steps = TECHNIQUE_MAP[parent_id][0].get("investigation_steps", [])

        results.append({
            "technique_id": tech["id"],
            "technique_name": tech["name"],
            "tactic_id": tactic_id,
            "tactic_name": tactic_name,
            "is_subtechnique": is_sub,
            "parent_technique_id": parent_id,
            "confidence": confidence,
            "confidence_score": round(score, 3),
            "matched_keywords": matched,
            "explanation": explanation,
            "indicators_found": indicators,
            "investigation_steps": inv_steps,
        })

    # Sort: High > Medium > Low, then by score
    _order = {"High": 3, "Medium": 2, "Low": 1}
    results.sort(key=lambda r: (_order.get(r["confidence"], 0), r["confidence_score"]), reverse=True)
    return results[:max_results]


def get_all_tactics() -> list[dict]:
    return TACTICS


def get_all_techniques() -> list[dict]:
    return TECHNIQUES


def get_technique_by_id(tid: str) -> Optional[dict]:
    entry = TECHNIQUE_MAP.get(tid)
    return entry[0] if entry else None
