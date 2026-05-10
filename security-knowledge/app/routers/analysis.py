import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import AuthContext, require_read, require_write
from app.database import get_db
from app.models.claims import Claim
from app.models.evidence import Evidence


router = APIRouter(prefix="/analysis", tags=["analysis"])


class AnalysisRequest(BaseModel):
    """Submit structured LLM analysis with provenance tracking."""
    entity_id: uuid.UUID
    findings: list[dict]  # Each: {statement, finding_type, confidence_raw, verification_status, evidence_text, llm_model}
    source_kind: str = "llm_analysis"
    llm_model: str = "unknown"
    # Confidence multiplier for LLM (always 0.5, can be lower for stacked LLM)
    confidence_multiplier: float = 0.5


class AnalysisResponse(BaseModel):
    entity_id: uuid.UUID
    claims_created: int
    evidence_created: int
    claim_ids: list[uuid.UUID] = []
    errors: list[str] = []


@router.post("/submit", response_model=AnalysisResponse)
async def submit_analysis(
    body: AnalysisRequest,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext | dict = Depends(require_write),
):
    """Submit LLM analysis findings as claims + evidence with provenance.

    Each finding becomes:
    - A claim with claim_type=source_kind, confidence=raw*multiplier (capped at 0.5 for llm_analysis)
    - An evidence record with LLM model tag and source_url=llm://model/hash
    """
    tenant_id = str(auth.tenant_id) if hasattr(auth, "tenant_id") else str(auth["tenant_id"])
    claims_created = 0
    evidence_created = 0
    claim_ids = []
    errors = []
    cap = 0.5 if body.source_kind == "llm_analysis" else 1.0

    for finding in body.findings:
        try:
            raw_conf = finding.get("confidence_raw", 0.5)
            adjusted = min(raw_conf * body.confidence_multiplier, cap)

            stmt = finding.get("statement", "")
            finding_type = finding.get("finding_type", "general")
            llm_model = finding.get("llm_model", body.llm_model)
            evidence_text = finding.get("evidence_text", "")
            verification = finding.get("verification_status", "unverified")
            subject = finding.get("subject")
            predicate = finding.get("predicate")
            object_ = finding.get("object")

            # Build value JSONB
            value = {"assertion": stmt, "source_kind": body.source_kind, "llm_model": llm_model}
            if finding_type:
                value["finding_type"] = finding_type
            if verification:
                value["verification_status"] = verification
            if subject:
                value["subject"] = subject
            if predicate:
                value["predicate"] = predicate
            if object_:
                value["object"] = object_

            # Create claim
            claim = Claim(
                tenant_id=tenant_id,
                entity_id=body.entity_id,
                claim_type=body.source_kind,
                value=value,
                confidence=adjusted,
            )
            db.add(claim)
            await db.flush()
            await db.refresh(claim)
            claim_ids.append(claim.id)
            claims_created += 1

            # Create evidence
            if evidence_text:
                import hashlib
                qhash = hashlib.sha256(stmt.encode()).hexdigest()[:12]
                ev = Evidence(
                    tenant_id=tenant_id,
                    entity_id=body.entity_id,
                    claim_id=claim.id,
                    title=f"LLM Analysis: {llm_model}",
                    content=f"[{verification.upper()}] {evidence_text}",
                    source_url=f"llm://{llm_model}/{qhash}",
                    confidence=adjusted,
                )
                db.add(ev)
                evidence_created += 1

        except Exception as e:
            errors.append(f"Finding {finding.get('statement', '?')[:30]}: {e}")

    return AnalysisResponse(
        entity_id=body.entity_id,
        claims_created=claims_created,
        evidence_created=evidence_created,
        claim_ids=claim_ids,
        errors=errors,
    )


class LlmClaimsSummary(BaseModel):
    entity_id: uuid.UUID
    total_llm_claims: int
    avg_confidence: float
    models_used: list[str]
    unverified_count: int


@router.get("/llm-summary/{entity_id}", response_model=LlmClaimsSummary)
async def llm_claims_summary(
    entity_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext | dict = Depends(require_read),
):
    """Summary of LLM-sourced claims for an entity."""
    tenant_id = str(auth.tenant_id) if hasattr(auth, "tenant_id") else str(auth["tenant_id"])
    result = await db.execute(
        select(Claim)
        .where(Claim.entity_id == entity_id, Claim.tenant_id == tenant_id, Claim.claim_type == "llm_analysis")
    )
    claims = result.scalars().all()
    models = set()
    unverified = 0
    total_conf = 0.0
    for c in claims:
        v = c.value if isinstance(c.value, dict) else {}
        m = v.get("llm_model", "unknown")
        if m:
            models.add(m)
        vs = v.get("verification_status", "")
        if vs == "unverified":
            unverified += 1
        total_conf += c.confidence
    return LlmClaimsSummary(
        entity_id=entity_id,
        total_llm_claims=len(claims),
        avg_confidence=total_conf / len(claims) if claims else 0.0,
        models_used=sorted(models),
        unverified_count=unverified,
    )
