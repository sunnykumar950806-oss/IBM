"""
FastAPI router: MITRE ATT&CK technique and tactic reference endpoints.
"""
from fastapi import APIRouter, HTTPException, Query
from app.models.schemas import TechniqueRefSchema, TacticRefSchema
from app.services.mitre_mapper import get_all_tactics, get_all_techniques, get_technique_by_id

router = APIRouter(prefix="/api", tags=["mitre"])


@router.get("/tactics", response_model=list[TacticRefSchema])
def list_tactics():
    """Return all MITRE ATT&CK tactics."""
    return get_all_tactics()


@router.get("/techniques", response_model=list[TechniqueRefSchema])
def list_techniques(search: str = Query(None)):
    """Return all techniques (with sub-techniques). Optionally filter by name."""
    techniques = get_all_techniques()
    if search:
        sl = search.lower()
        techniques = [
            t for t in techniques
            if sl in t["name"].lower() or sl in t["id"].lower()
            or any(sl in s["name"].lower() or sl in s["id"].lower() for s in t.get("sub_techniques", []))
        ]
    return techniques


@router.get("/techniques/{technique_id}", response_model=TechniqueRefSchema)
def get_technique(technique_id: str):
    """Return a single technique or sub-technique by ID."""
    tech = get_technique_by_id(technique_id.upper())
    if not tech:
        raise HTTPException(status_code=404, detail="Technique not found")
    # Normalise to match schema (top-level fields only)
    return {
        "id": tech.get("id", ""),
        "name": tech.get("name", ""),
        "tactic_ids": tech.get("tactic_ids", []),
        "tactic_names": tech.get("tactic_names", []),
        "description": tech.get("description", ""),
        "url": tech.get("url", f"https://attack.mitre.org/techniques/{tech.get('id', '')}"),
        "platforms": tech.get("platforms", []),
        "data_sources": tech.get("data_sources", []),
        "mitigations": tech.get("mitigations", []),
        "investigation_steps": tech.get("investigation_steps", []),
        "sub_techniques": tech.get("sub_techniques", []),
    }
