"""
Pydantic schemas for request/response validation.
"""
from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, field_validator


# ── Request schemas ──────────────────────────────────────────────────────────

class AlertAnalyzeRequest(BaseModel):
    raw_input: str
    input_format: str = "text"   # "text" or "json"

    @field_validator("input_format")
    @classmethod
    def validate_format(cls, v: str) -> str:
        if v not in ("text", "json"):
            raise ValueError("input_format must be 'text' or 'json'")
        return v


# ── Response schemas ─────────────────────────────────────────────────────────

class SigmaRuleSchema(BaseModel):
    id: str
    title: str
    description: str
    level: str

    model_config = {"from_attributes": True}


class MitreMappingSchema(BaseModel):
    id: int
    technique_id: str
    technique_name: str
    tactic_id: Optional[str]
    tactic_name: Optional[str]
    is_subtechnique: bool
    parent_technique_id: Optional[str]
    confidence: str
    confidence_score: float
    matched_keywords: list[str]
    explanation: str
    indicators_found: list[str]
    investigation_steps: list[str]
    sigma_rules: list[SigmaRuleSchema]

    model_config = {"from_attributes": True}


class AlertSchema(BaseModel):
    id: int
    raw_input: str
    input_format: str
    alert_type: Optional[str]
    timestamp: datetime
    analyzed_at: Optional[datetime]
    username: Optional[str]
    source_ip: Optional[str]
    destination_ip: Optional[str]
    process_name: Optional[str]
    command_line: Optional[str]
    file_name: Optional[str]
    hostname: Optional[str]
    is_analyzed: bool
    mapping_count: int
    top_confidence: Optional[str]
    mappings: list[MitreMappingSchema] = []

    model_config = {"from_attributes": True}


class AlertListItemSchema(BaseModel):
    id: int
    alert_type: Optional[str]
    timestamp: datetime
    analyzed_at: Optional[datetime]
    is_analyzed: bool
    mapping_count: int
    top_confidence: Optional[str]
    raw_input: str
    source_ip: Optional[str]
    username: Optional[str]

    model_config = {"from_attributes": True}


# ── MITRE reference schemas ───────────────────────────────────────────────────

class TacticRefSchema(BaseModel):
    id: str
    name: str
    description: str


class SubTechniqueRefSchema(BaseModel):
    id: str
    name: str
    description: str
    investigation_steps: list[str]


class TechniqueRefSchema(BaseModel):
    id: str
    name: str
    tactic_ids: list[str]
    tactic_names: list[str]
    description: str
    url: str
    platforms: list[str]
    data_sources: list[str]
    mitigations: list[str]
    investigation_steps: list[str]
    sub_techniques: list[SubTechniqueRefSchema]


# ── Dashboard schema ──────────────────────────────────────────────────────────

class DashboardSchema(BaseModel):
    total_alerts: int
    mapped_alerts: int
    unmapped_alerts: int
    high_confidence_count: int
    medium_confidence_count: int
    low_confidence_count: int
    top_tactics: list[dict[str, Any]]
    top_techniques: list[dict[str, Any]]
    recent_alerts: list[AlertListItemSchema]


# ── Search schema ─────────────────────────────────────────────────────────────

class SearchResultSchema(BaseModel):
    total: int
    alerts: list[AlertListItemSchema]
