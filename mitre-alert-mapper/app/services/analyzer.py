"""
Alert analysis service: orchestrates parsing, mapping, and persistence.
"""
import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.db_models import Alert, MitreMapping, SigmaMatch
from app.services.alert_parser import parse_alert
from app.services.mitre_mapper import map_alert
from app.services.sigma_matcher import match_sigma_rules, get_sigma_rules_for_techniques


def analyze_and_store(raw_input: str, input_format: str, db: Session) -> Alert:
    """Parse, map, and persist an alert. Returns the saved Alert ORM object."""

    # 1. Parse
    parsed = parse_alert(raw_input, input_format)

    # 2. Create alert record
    alert = Alert(
        raw_input=raw_input,
        input_format=input_format,
        alert_type=parsed["alert_type"],
        timestamp=datetime.now(timezone.utc),
        analyzed_at=datetime.now(timezone.utc),
        username=parsed.get("username"),
        source_ip=parsed.get("source_ip"),
        destination_ip=parsed.get("destination_ip"),
        process_name=parsed.get("process_name"),
        command_line=parsed.get("command_line"),
        file_name=parsed.get("file_name"),
        hostname=parsed.get("hostname"),
        indicators_json=json.dumps(parsed.get("extra_indicators", {})),
        is_analyzed=True,
    )
    db.add(alert)
    db.flush()  # Get the auto-generated id

    # 3. Map to MITRE ATT&CK
    mappings_data = map_alert(raw_input, parsed)

    # 4. Sigma rule matching against alert text
    sigma_matches = match_sigma_rules(raw_input)
    sigma_by_technique: dict[str, list[dict]] = {}
    for sm in sigma_matches:
        for tid in sm.get("technique_ids", []):
            sigma_by_technique.setdefault(tid, []).append(sm)

    # 5. Persist mappings
    confidence_order = {"High": 3, "Medium": 2, "Low": 1}
    top_conf = "Low"

    for m_data in mappings_data:
        tid = m_data["technique_id"]
        # Gather sigma rules for this technique (from alert match + technique lookup)
        technique_sigma = sigma_by_technique.get(tid, [])
        # Also get sigma rules that cover the technique id directly
        extra_sigma = get_sigma_rules_for_techniques([tid])
        seen_sigma_ids: set[str] = set()
        combined_sigma: list[dict] = []
        for sr in technique_sigma + extra_sigma:
            if sr["id"] not in seen_sigma_ids:
                combined_sigma.append(sr)
                seen_sigma_ids.add(sr["id"])

        mapping = MitreMapping(
            alert_id=alert.id,
            technique_id=tid,
            technique_name=m_data["technique_name"],
            tactic_id=m_data.get("tactic_id"),
            tactic_name=m_data.get("tactic_name"),
            is_subtechnique=m_data.get("is_subtechnique", False),
            parent_technique_id=m_data.get("parent_technique_id"),
            confidence=m_data["confidence"],
            confidence_score=m_data["confidence_score"],
            matched_keywords=json.dumps(m_data["matched_keywords"]),
            explanation=m_data["explanation"],
            indicators_found=json.dumps(m_data["indicators_found"]),
            investigation_steps=json.dumps(m_data["investigation_steps"]),
            sigma_rules_json=json.dumps(combined_sigma),
        )
        db.add(mapping)

        # Track top confidence
        if confidence_order.get(m_data["confidence"], 0) > confidence_order.get(top_conf, 0):
            top_conf = m_data["confidence"]

    # 6. Persist sigma matches at alert level
    stored_sigma_ids: set[str] = set()
    for sm in sigma_matches:
        if sm["id"] not in stored_sigma_ids:
            db.add(SigmaMatch(
                alert_id=alert.id,
                sigma_rule_id=sm["id"],
                rule_title=sm["title"],
                rule_description=sm["description"],
                rule_level=sm["level"],
                technique_ids=json.dumps(sm.get("technique_ids", [])),
            ))
            stored_sigma_ids.add(sm["id"])

    # 7. Update summary fields
    alert.mapping_count = len(mappings_data)
    alert.top_confidence = top_conf if mappings_data else None

    db.commit()
    db.refresh(alert)
    return alert


def _alert_to_dict(alert: Alert) -> dict:
    """Convert an Alert ORM object to a serialisable dict (for responses)."""
    mappings = []
    for m in alert.mappings:
        sigma_rules_raw = m.get_sigma_rules()
        mappings.append({
            "id": m.id,
            "technique_id": m.technique_id,
            "technique_name": m.technique_name,
            "tactic_id": m.tactic_id,
            "tactic_name": m.tactic_name,
            "is_subtechnique": m.is_subtechnique,
            "parent_technique_id": m.parent_technique_id,
            "confidence": m.confidence,
            "confidence_score": m.confidence_score,
            "matched_keywords": m.get_matched_keywords(),
            "explanation": m.explanation or "",
            "indicators_found": m.get_indicators_found(),
            "investigation_steps": m.get_investigation_steps(),
            "sigma_rules": sigma_rules_raw,
        })

    return {
        "id": alert.id,
        "raw_input": alert.raw_input,
        "input_format": alert.input_format,
        "alert_type": alert.alert_type,
        "timestamp": alert.timestamp,
        "analyzed_at": alert.analyzed_at,
        "username": alert.username,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "process_name": alert.process_name,
        "command_line": alert.command_line,
        "file_name": alert.file_name,
        "hostname": alert.hostname,
        "is_analyzed": alert.is_analyzed,
        "mapping_count": alert.mapping_count,
        "top_confidence": alert.top_confidence,
        "mappings": mappings,
    }
