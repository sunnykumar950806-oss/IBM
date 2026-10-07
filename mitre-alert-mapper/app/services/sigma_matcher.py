"""
Sigma rule matcher: matches alert text against a local library of Sigma rules.
"""
import json
from pathlib import Path

_SIGMA_PATH = Path(__file__).parent.parent / "data" / "sigma_rules.json"

with open(_SIGMA_PATH, "r") as _f:
    _SIGMA_RULES: list[dict] = json.load(_f)


def match_sigma_rules(text: str) -> list[dict]:
    """
    Return Sigma rules that match the given alert text.

    Each returned dict has: id, title, description, level, technique_ids.
    """
    text_lower = text.lower()
    matches: list[dict] = []

    for rule in _SIGMA_RULES:
        keywords: list[str] = rule.get("keywords", [])
        if any(kw.lower() in text_lower for kw in keywords):
            matches.append({
                "id": rule["id"],
                "title": rule["title"],
                "description": rule["description"],
                "level": rule["level"],
                "technique_ids": rule.get("technique_ids", []),
            })

    return matches


def get_sigma_rules_for_techniques(technique_ids: list[str]) -> list[dict]:
    """Return Sigma rules associated with any of the given technique IDs."""
    tid_set = set(technique_ids)
    results: list[dict] = []
    for rule in _SIGMA_RULES:
        if tid_set.intersection(set(rule.get("technique_ids", []))):
            results.append({
                "id": rule["id"],
                "title": rule["title"],
                "description": rule["description"],
                "level": rule["level"],
                "technique_ids": rule.get("technique_ids", []),
            })
    return results
