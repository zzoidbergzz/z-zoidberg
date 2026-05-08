"""POST /api/v1/import/corpus — bulk corpus import endpoint.

Accepts a multipart tar.zst archive or a JSON payload describing a
pre-extracted corpus directory on the server filesystem.

Remote agents use this to push a Mode A research package and receive
an import summary.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from app.auth.dependencies import AuthContext, require_write

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/import", tags=["import"])


@router.post(
    "/corpus",
    summary="Bulk import a Mode A research corpus package",
    response_class=JSONResponse,
    status_code=200,
)
async def import_corpus(
    archive: Annotated[UploadFile | None, File(description="tar.zst corpus archive")] = None,
    tenant_id: Annotated[str | None, Form()] = None,
    dry_run: Annotated[bool, Form()] = False,
    auth: AuthContext = Depends(require_write),
):
    """Import a corpus package (tar.zst or multipart form with JSONL files).

    - Upload a tar.zst archive produced by the deep-research-prompt workflow.
    - Or POST individual JSONL files as separate form fields.
    - Returns an import summary with per-type counts.
    - Idempotent: re-running over an already-imported corpus writes nothing new.
    """
    from app.cli.import_corpus import _extract_tarzst, _validate_package, import_corpus_package

    effective_tenant = tenant_id or str(auth.tenant_id)

    if archive is None:
        raise HTTPException(
            status_code=422,
            detail="Provide an 'archive' file field (tar.zst corpus archive).",
        )

    with tempfile.TemporaryDirectory(prefix="corpus_import_") as tmp:
        tmp_path = Path(tmp)
        archive_path = tmp_path / "corpus.tar.zst"
        content = await archive.read()
        archive_path.write_bytes(content)

        pkg_dir = tmp_path / "pkg"
        pkg_dir.mkdir()

        try:
            _extract_tarzst(archive_path, pkg_dir)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"Failed to extract archive: {exc}") from exc

        # If tar extracted a single sub-directory, descend
        children = list(pkg_dir.iterdir())
        if len(children) == 1 and children[0].is_dir():
            pkg_dir = children[0]

        errors = _validate_package(pkg_dir)
        if errors:
            raise HTTPException(status_code=422, detail={"validation_errors": errors})

        summary = await import_corpus_package(
            pkg_dir,
            effective_tenant,
            dry_run=dry_run,
        )

    logger.info(
        "corpus_import_complete",
        tenant_id=effective_tenant,
        dry_run=dry_run,
        entities=summary.get("entities"),
        claims=summary.get("claims"),
    )
    return summary
