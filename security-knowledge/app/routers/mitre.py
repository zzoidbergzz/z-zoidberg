"""MITRE ATT&CK REST API router."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.dependencies import AuthContext, Scope, require_scope
from app.services import mitre_attack

router = APIRouter(prefix="/mitre", tags=["mitre-attack"])

_NOT_LOADED_MSG = (
    "MITRE ATT&CK data not loaded for domain {domain}. "
    "Call GET /api/v1/mitre/download?domain={domain} first."
)


def _domain_503(domain: str) -> HTTPException:
    return HTTPException(status_code=503, detail=_NOT_LOADED_MSG.format(domain=domain))


def _guard(domain: str, result: list | dict | None):
    """Raise 503 when data is missing (empty list could mean empty domain)."""
    return result


# ── Status ──────────────────────────────────────────────────────────────────

@router.get("/status")
async def get_status(auth: AuthContext = Depends(require_scope(Scope.read))):
    loaded = mitre_attack.get_loaded_domains()
    return {
        "loaded_domains": loaded,
        "data_dir": mitre_attack.get_data_dir(),
        "available_domains": list(mitre_attack.STIX_URLS.keys()),
    }


# ── Download ─────────────────────────────────────────────────────────────────

@router.get("/download")
async def download_stix(
    domain: str = Query("enterprise"),
    auth: AuthContext = Depends(require_scope(Scope.admin)),
):
    try:
        path = await mitre_attack.ensure_data_downloaded(domain)
        # Force reload
        mitre_attack._instances.pop(domain, None)
        await mitre_attack.get_attack_data(domain)
        return {"status": "ok", "domain": domain, "path": path}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ── Techniques ───────────────────────────────────────────────────────────────

@router.get("/techniques")
async def list_techniques(
    domain: str = Query("enterprise"),
    tactic: Optional[str] = Query(None),
    platform: Optional[str] = Query(None),
    include_description: bool = Query(False),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        if tactic:
            return await mitre_attack.get_techniques_by_tactic(tactic, domain, include_description)
        if platform:
            return await mitre_attack.get_techniques_by_platform(platform, domain, include_description)
        return await mitre_attack.get_all_techniques(domain, include_description)
    except ValueError as exc:
        raise _domain_503(domain) from exc
    except Exception as exc:
        if "not loaded" in str(exc).lower() or "no such file" in str(exc).lower():
            raise _domain_503(domain) from exc
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/techniques/{attack_id}/groups")
async def technique_groups(
    attack_id: str,
    domain: str = Query("enterprise"),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        obj = await mitre_attack.get_object_by_attack_id(attack_id, domain)
        if obj is None:
            raise HTTPException(status_code=404, detail=f"Technique {attack_id} not found")
        return await mitre_attack.get_groups_using_technique(obj["stix_id"], domain)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/techniques/{attack_id}/mitigations")
async def technique_mitigations(
    attack_id: str,
    domain: str = Query("enterprise"),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        obj = await mitre_attack.get_object_by_attack_id(attack_id, domain)
        if obj is None:
            raise HTTPException(status_code=404, detail=f"Technique {attack_id} not found")
        return await mitre_attack.get_mitigations_mitigating_technique(obj["stix_id"], domain)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/techniques/{attack_id}/detections")
async def technique_detections(
    attack_id: str,
    domain: str = Query("enterprise"),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        obj = await mitre_attack.get_object_by_attack_id(attack_id, domain)
        if obj is None:
            raise HTTPException(status_code=404, detail=f"Technique {attack_id} not found")
        return await mitre_attack.get_datacomponents_detecting_technique(obj["stix_id"], domain)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/techniques/{attack_id}/examples")
async def technique_examples(
    attack_id: str,
    domain: str = Query("enterprise"),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        obj = await mitre_attack.get_object_by_attack_id(attack_id, domain)
        if obj is None:
            raise HTTPException(status_code=404, detail=f"Technique {attack_id} not found")
        return await mitre_attack.get_procedure_examples_by_technique(obj["stix_id"], domain)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/techniques/{attack_id}/campaigns")
async def technique_campaigns(
    attack_id: str,
    domain: str = Query("enterprise"),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        obj = await mitre_attack.get_object_by_attack_id(attack_id, domain)
        if obj is None:
            raise HTTPException(status_code=404, detail=f"Technique {attack_id} not found")
        return await mitre_attack.get_campaigns_using_technique(obj["stix_id"], domain)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/techniques/{attack_id}")
async def get_technique(
    attack_id: str,
    domain: str = Query("enterprise"),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        obj = await mitre_attack.get_object_by_attack_id(attack_id, domain)
        if obj is None:
            raise HTTPException(status_code=404, detail=f"Object {attack_id} not found")
        return obj
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ── Subtechniques ─────────────────────────────────────────────────────────────

@router.get("/subtechniques/{technique_id}")
async def list_subtechniques(
    technique_id: str,
    domain: str = Query("enterprise"),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        obj = await mitre_attack.get_object_by_attack_id(technique_id, domain)
        if obj is None:
            raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")
        return await mitre_attack.get_subtechniques_of_technique(obj["stix_id"], domain)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ── Groups ────────────────────────────────────────────────────────────────────

@router.get("/groups")
async def list_groups(
    domain: str = Query("enterprise"),
    include_description: bool = Query(False),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        return await mitre_attack.get_all_groups(domain, include_description)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/groups/{group_id}/techniques")
async def group_techniques(
    group_id: str,
    domain: str = Query("enterprise"),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        obj = await mitre_attack.get_object_by_attack_id(group_id, domain)
        if obj is None:
            raise HTTPException(status_code=404, detail=f"Group {group_id} not found")
        return await mitre_attack.get_techniques_used_by_group(obj["stix_id"], domain)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/groups/{group_id}/software")
async def group_software(
    group_id: str,
    domain: str = Query("enterprise"),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        obj = await mitre_attack.get_object_by_attack_id(group_id, domain)
        if obj is None:
            raise HTTPException(status_code=404, detail=f"Group {group_id} not found")
        return await mitre_attack.get_software_used_by_group(obj["stix_id"], domain)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/groups/{group_id}/campaigns")
async def group_campaigns(
    group_id: str,
    domain: str = Query("enterprise"),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        obj = await mitre_attack.get_object_by_attack_id(group_id, domain)
        if obj is None:
            raise HTTPException(status_code=404, detail=f"Group {group_id} not found")
        return await mitre_attack.get_campaigns_attributed_to_group(obj["stix_id"], domain)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/groups/{group_id}")
async def get_group(
    group_id: str,
    domain: str = Query("enterprise"),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        obj = await mitre_attack.get_object_by_attack_id(group_id, domain)
        if obj is None:
            raise HTTPException(status_code=404, detail=f"Group {group_id} not found")
        return obj
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ── Software ──────────────────────────────────────────────────────────────────

@router.get("/software")
async def list_software(
    domain: str = Query("enterprise"),
    include_description: bool = Query(False),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        return await mitre_attack.get_all_software(domain, include_description)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/software/{software_id}/techniques")
async def software_techniques(
    software_id: str,
    domain: str = Query("enterprise"),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        obj = await mitre_attack.get_object_by_attack_id(software_id, domain)
        if obj is None:
            raise HTTPException(status_code=404, detail=f"Software {software_id} not found")
        return await mitre_attack.get_techniques_used_by_software(obj["stix_id"], domain)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/software/{software_id}")
async def get_software(
    software_id: str,
    domain: str = Query("enterprise"),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        obj = await mitre_attack.get_object_by_attack_id(software_id, domain)
        if obj is None:
            raise HTTPException(status_code=404, detail=f"Software {software_id} not found")
        return obj
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ── Campaigns ─────────────────────────────────────────────────────────────────

@router.get("/campaigns")
async def list_campaigns(
    domain: str = Query("enterprise"),
    include_description: bool = Query(False),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        return await mitre_attack.get_all_campaigns(domain, include_description)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/campaigns/{campaign_id}/techniques")
async def campaign_techniques(
    campaign_id: str,
    domain: str = Query("enterprise"),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        obj = await mitre_attack.get_object_by_attack_id(campaign_id, domain)
        if obj is None:
            raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")
        return await mitre_attack.get_techniques_used_by_campaign(obj["stix_id"], domain)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/campaigns/{campaign_id}")
async def get_campaign(
    campaign_id: str,
    domain: str = Query("enterprise"),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        obj = await mitre_attack.get_object_by_attack_id(campaign_id, domain)
        if obj is None:
            raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")
        return obj
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ── Mitigations ───────────────────────────────────────────────────────────────

@router.get("/mitigations")
async def list_mitigations(
    domain: str = Query("enterprise"),
    include_description: bool = Query(False),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        return await mitre_attack.get_all_mitigations(domain, include_description)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/mitigations/{mitigation_id}/techniques")
async def mitigation_techniques(
    mitigation_id: str,
    domain: str = Query("enterprise"),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        obj = await mitre_attack.get_object_by_attack_id(mitigation_id, domain)
        if obj is None:
            raise HTTPException(status_code=404, detail=f"Mitigation {mitigation_id} not found")
        return await mitre_attack.get_techniques_mitigated_by_mitigation(obj["stix_id"], domain)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ── Tactics ───────────────────────────────────────────────────────────────────

@router.get("/tactics")
async def list_tactics(
    domain: str = Query("enterprise"),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        return await mitre_attack.get_all_tactics(domain)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ── Search ────────────────────────────────────────────────────────────────────

@router.get("/search")
async def search_mitre(
    q: Optional[str] = Query(None, description="Search by name"),
    content: Optional[str] = Query(None, description="Search by content"),
    domain: str = Query("enterprise"),
    type: Optional[str] = Query(None, description="Filter by STIX type"),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        results: list[dict] = []
        if q:
            results = await mitre_attack.get_objects_by_name(q, domain)
        elif content:
            results = await mitre_attack.get_objects_by_content(content, domain)
        if type:
            results = [r for r in results if r.get("type") == type]
        return results
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ── Revoked ───────────────────────────────────────────────────────────────────

@router.get("/revoked")
async def list_revoked(
    domain: str = Query("enterprise"),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        return await mitre_attack.get_revoked_techniques(domain)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ── Changes ───────────────────────────────────────────────────────────────────

@router.get("/changes")
async def list_changes(
    since: str = Query(..., description="YYYY-MM-DD"),
    type: str = Query("created", description="'created' or 'modified'"),
    domain: str = Query("enterprise"),
    auth: AuthContext = Depends(require_scope(Scope.read)),
):
    try:
        if type == "created":
            return await mitre_attack.get_objects_created_after(since, domain)
        elif type == "modified":
            return await mitre_attack.get_objects_modified_after(since, domain)
        else:
            raise HTTPException(status_code=400, detail="type must be 'created' or 'modified'")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
