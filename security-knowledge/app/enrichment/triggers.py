from app.enrichment.registry import list_providers
import structlog

logger = structlog.get_logger(__name__)


async def trigger_enrichment(entity_kind: str, entity_value: str, providers: list[str] | None = None) -> None:
    from app.enrichment.service import EnrichmentService
    available = list_providers()
    selected = providers if providers else available
    for name in selected:
        if name in available:
            logger.info("enrichment_triggered", provider=name, entity_kind=entity_kind)
