"""MITRE ATT&CK data service.

Downloads STIX data lazily on first use (cached to MITRE_ATTACK_DATA_DIR).
Provides async-friendly wrappers around mitreattack-python queries.
Domains: enterprise (default), mobile, ics.
"""
from __future__ import annotations

import asyncio
import logging
import os
from functools import partial
from pathlib import Path
from typing import Any

from app.config import settings

logger = logging.getLogger(__name__)

_instances: dict[str, Any] = {}  # domain -> MitreAttackData

STIX_URLS = {
    "enterprise": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    "mobile": "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
    "ics": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
}


def _get_data_dir() -> Path:
    raw = settings.MITRE_ATTACK_DATA_DIR
    if raw:
        return Path(raw).expanduser()
    return Path.home() / ".cache" / "sk-mitre-data"


def _stix_file_path(domain: str) -> Path:
    return _get_data_dir() / f"{domain}-attack.json"


def _download_stix_sync(domain: str) -> str:
    import urllib.request

    url = STIX_URLS.get(domain)
    if not url:
        raise ValueError(f"Unknown domain: {domain}. Valid: {list(STIX_URLS)}")

    path = _stix_file_path(domain)
    path.parent.mkdir(parents=True, exist_ok=True)

    logger.info("Downloading MITRE ATT&CK STIX data for domain=%s from %s", domain, url)
    urllib.request.urlretrieve(url, str(path))
    logger.info("MITRE ATT&CK STIX data saved to %s", path)
    return str(path)


def _load_attack_data_sync(domain: str) -> Any:
    from mitreattack.stix20 import MitreAttackData

    path = _stix_file_path(domain)
    if not path.exists():
        _download_stix_sync(domain)
    return MitreAttackData(str(path))


async def ensure_data_downloaded(domain: str = "enterprise") -> str:
    """Download STIX data if not present. Returns file path."""
    loop = asyncio.get_event_loop()
    path = _stix_file_path(domain)
    if not path.exists():
        await loop.run_in_executor(None, _download_stix_sync, domain)
    return str(path)


async def get_attack_data(domain: str = "enterprise") -> Any:
    """Return MitreAttackData instance for domain, loading lazily."""
    if domain not in _instances:
        loop = asyncio.get_event_loop()
        instance = await loop.run_in_executor(None, _load_attack_data_sync, domain)
        _instances[domain] = instance
    return _instances[domain]


async def preload_if_cached() -> None:
    """Silently pre-load domains whose STIX files already exist locally."""
    for domain in STIX_URLS:
        if _stix_file_path(domain).exists():
            try:
                await get_attack_data(domain)
                logger.info("Pre-loaded MITRE ATT&CK data for domain=%s", domain)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to pre-load MITRE ATT&CK domain=%s: %s", domain, exc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_dict(obj: Any, include_description: bool = True) -> dict:
    """Convert a STIX object to a plain serialisable dict."""
    if obj is None:
        return {}

    d: dict = {}

    # stix_id
    d["stix_id"] = getattr(obj, "id", None)

    # attack_id  — look in external_references
    attack_id = None
    for ref in getattr(obj, "external_references", []):
        src = getattr(ref, "source_name", "") or ref.get("source_name", "")
        if src == "mitre-attack":
            ext_id = getattr(ref, "external_id", None) or ref.get("external_id")
            if ext_id:
                attack_id = ext_id
                break
    d["attack_id"] = attack_id

    d["name"] = getattr(obj, "name", None)
    d["type"] = getattr(obj, "type", None)

    desc = getattr(obj, "description", "") or ""
    if include_description:
        d["description"] = desc
    else:
        d["description"] = desc[:500] if desc else ""

    # tactics
    kill_chain = getattr(obj, "kill_chain_phases", []) or []
    d["tactics"] = [
        getattr(kc, "phase_name", None) or kc.get("phase_name")
        for kc in kill_chain
    ]

    # platforms
    d["platforms"] = list(getattr(obj, "x_mitre_platforms", []) or [])

    # aliases
    aliases = getattr(obj, "aliases", None) or getattr(obj, "x_mitre_aliases", None)
    if aliases:
        d["aliases"] = list(aliases)

    # revoked / deprecated
    d["revoked"] = bool(getattr(obj, "revoked", False))
    d["deprecated"] = bool(getattr(obj, "x_mitre_deprecated", False))

    # created / modified
    created = getattr(obj, "created", None)
    modified = getattr(obj, "modified", None)
    d["created"] = str(created) if created else None
    d["modified"] = str(modified) if modified else None

    # subtechnique
    d["is_subtechnique"] = bool(getattr(obj, "x_mitre_is_subtechnique", False))

    return d


def _safe_list(items: Any, include_description: bool = False) -> list[dict]:
    if not items:
        return []
    return [_to_dict(i, include_description) for i in items]


def _relationship_list(entries: Any, include_description: bool = False) -> list[dict]:
    """Handle RelationshipEntry list [{object: ..., relationships: [...]}]."""
    if not entries:
        return []
    result = []
    for entry in entries:
        obj = entry.get("object") if isinstance(entry, dict) else getattr(entry, "object", None)
        if obj is not None:
            result.append(_to_dict(obj, include_description))
    return result


async def _run(fn, *args, **kwargs) -> Any:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, partial(fn, *args, **kwargs))


# ---------------------------------------------------------------------------
# Public query functions
# ---------------------------------------------------------------------------

async def get_object_by_attack_id(attack_id: str, domain: str = "enterprise") -> dict | None:
    try:
        data = await get_attack_data(domain)
        obj = await _run(data.get_object_by_attack_id, attack_id, None)
        return _to_dict(obj) if obj else None
    except Exception as exc:
        logger.debug("get_object_by_attack_id(%s): %s", attack_id, exc)
        return None


async def get_object_by_stix_id(stix_id: str, domain: str = "enterprise") -> dict | None:
    try:
        data = await get_attack_data(domain)
        obj = await _run(data.get_object_by_stix_id, stix_id)
        return _to_dict(obj) if obj else None
    except Exception as exc:
        logger.debug("get_object_by_stix_id(%s): %s", stix_id, exc)
        return None


async def get_objects_by_name(name: str, domain: str = "enterprise") -> list[dict]:
    try:
        data = await get_attack_data(domain)
        items = await _run(data.get_objects_by_name, name)
        return _safe_list(items)
    except Exception as exc:
        logger.debug("get_objects_by_name(%s): %s", name, exc)
        return []


async def get_objects_by_content(content: str, domain: str = "enterprise") -> list[dict]:
    try:
        data = await get_attack_data(domain)
        items = await _run(data.get_objects_by_content, content)
        return _safe_list(items)
    except Exception as exc:
        logger.debug("get_objects_by_content(%s): %s", content, exc)
        return []


async def get_techniques_used_by_group(group_id: str, domain: str = "enterprise") -> list[dict]:
    try:
        data = await get_attack_data(domain)
        entries = await _run(data.get_techniques_used_by_group, group_id)
        return _relationship_list(entries)
    except Exception as exc:
        logger.debug("get_techniques_used_by_group(%s): %s", group_id, exc)
        return []


async def get_software_used_by_group(group_id: str, domain: str = "enterprise") -> list[dict]:
    try:
        data = await get_attack_data(domain)
        entries = await _run(data.get_software_used_by_group, group_id)
        return _relationship_list(entries)
    except Exception as exc:
        logger.debug("get_software_used_by_group(%s): %s", group_id, exc)
        return []


async def get_campaigns_attributed_to_group(group_id: str, domain: str = "enterprise") -> list[dict]:
    try:
        data = await get_attack_data(domain)
        entries = await _run(data.get_campaigns_attributed_to_group, group_id)
        return _relationship_list(entries)
    except Exception as exc:
        logger.debug("get_campaigns_attributed_to_group(%s): %s", group_id, exc)
        return []


async def get_groups_using_technique(technique_id: str, domain: str = "enterprise") -> list[dict]:
    try:
        data = await get_attack_data(domain)
        entries = await _run(data.get_groups_using_technique, technique_id)
        return _relationship_list(entries)
    except Exception as exc:
        logger.debug("get_groups_using_technique(%s): %s", technique_id, exc)
        return []


async def get_groups_using_software(software_id: str, domain: str = "enterprise") -> list[dict]:
    try:
        data = await get_attack_data(domain)
        entries = await _run(data.get_groups_using_software, software_id)
        return _relationship_list(entries)
    except Exception as exc:
        logger.debug("get_groups_using_software(%s): %s", software_id, exc)
        return []


async def get_techniques_used_by_software(software_id: str, domain: str = "enterprise") -> list[dict]:
    try:
        data = await get_attack_data(domain)
        entries = await _run(data.get_techniques_used_by_software, software_id)
        return _relationship_list(entries)
    except Exception as exc:
        logger.debug("get_techniques_used_by_software(%s): %s", software_id, exc)
        return []


async def get_all_techniques(domain: str = "enterprise", include_description: bool = False) -> list[dict]:
    try:
        data = await get_attack_data(domain)
        items = await _run(data.get_techniques, include_subtechniques=True, remove_revoked_deprecated=False)
        return _safe_list(items, include_description)
    except Exception as exc:
        logger.debug("get_all_techniques: %s", exc)
        return []


async def get_all_subtechniques(domain: str = "enterprise", include_description: bool = False) -> list[dict]:
    try:
        data = await get_attack_data(domain)
        items = await _run(data.get_subtechniques)
        return _safe_list(items, include_description)
    except Exception as exc:
        logger.debug("get_all_subtechniques: %s", exc)
        return []


async def get_all_groups(domain: str = "enterprise", include_description: bool = False) -> list[dict]:
    try:
        data = await get_attack_data(domain)
        items = await _run(data.get_groups)
        return _safe_list(items, include_description)
    except Exception as exc:
        logger.debug("get_all_groups: %s", exc)
        return []


async def get_all_software(domain: str = "enterprise", include_description: bool = False) -> list[dict]:
    try:
        data = await get_attack_data(domain)
        items = await _run(data.get_software)
        return _safe_list(items, include_description)
    except Exception as exc:
        logger.debug("get_all_software: %s", exc)
        return []


async def get_all_mitigations(domain: str = "enterprise", include_description: bool = False) -> list[dict]:
    try:
        data = await get_attack_data(domain)
        items = await _run(data.get_mitigations)
        return _safe_list(items, include_description)
    except Exception as exc:
        logger.debug("get_all_mitigations: %s", exc)
        return []


async def get_all_tactics(domain: str = "enterprise") -> list[dict]:
    try:
        data = await get_attack_data(domain)
        items = await _run(data.get_tactics)
        return _safe_list(items, True)
    except Exception as exc:
        logger.debug("get_all_tactics: %s", exc)
        return []


async def get_all_campaigns(domain: str = "enterprise", include_description: bool = False) -> list[dict]:
    try:
        data = await get_attack_data(domain)
        items = await _run(data.get_campaigns)
        return _safe_list(items, include_description)
    except Exception as exc:
        logger.debug("get_all_campaigns: %s", exc)
        return []


async def get_subtechniques_of_technique(technique_id: str, domain: str = "enterprise") -> list[dict]:
    try:
        data = await get_attack_data(domain)
        items = await _run(data.get_subtechniques_of_technique, technique_id)
        return _safe_list(items)
    except Exception as exc:
        logger.debug("get_subtechniques_of_technique(%s): %s", technique_id, exc)
        return []


async def get_parent_technique_of_subtechnique(subtechnique_id: str, domain: str = "enterprise") -> dict | None:
    try:
        data = await get_attack_data(domain)
        obj = await _run(data.get_parent_technique_of_subtechnique, subtechnique_id)
        return _to_dict(obj) if obj else None
    except Exception as exc:
        logger.debug("get_parent_technique_of_subtechnique(%s): %s", subtechnique_id, exc)
        return None


async def get_techniques_by_tactic(tactic: str, domain: str = "enterprise", include_description: bool = False) -> list[dict]:
    try:
        data = await get_attack_data(domain)
        items = await _run(data.get_techniques_by_tactic, tactic, domain, remove_revoked_deprecated=False)
        return _safe_list(items, include_description)
    except Exception as exc:
        logger.debug("get_techniques_by_tactic(%s): %s", tactic, exc)
        return []


async def get_techniques_by_platform(platform: str, domain: str = "enterprise", include_description: bool = False) -> list[dict]:
    try:
        data = await get_attack_data(domain)
        items = await _run(data.get_techniques_by_platform, platform, remove_revoked_deprecated=False)
        return _safe_list(items, include_description)
    except Exception as exc:
        logger.debug("get_techniques_by_platform(%s): %s", platform, exc)
        return []


async def get_mitigations_mitigating_technique(technique_id: str, domain: str = "enterprise") -> list[dict]:
    try:
        data = await get_attack_data(domain)
        entries = await _run(data.get_mitigations_mitigating_technique, technique_id)
        return _relationship_list(entries)
    except Exception as exc:
        logger.debug("get_mitigations_mitigating_technique(%s): %s", technique_id, exc)
        return []


async def get_datacomponents_detecting_technique(technique_id: str, domain: str = "enterprise") -> list[dict]:
    try:
        data = await get_attack_data(domain)
        entries = await _run(data.get_datacomponents_detecting_technique, technique_id)
        return _relationship_list(entries)
    except Exception as exc:
        logger.debug("get_datacomponents_detecting_technique(%s): %s", technique_id, exc)
        return []


async def get_procedure_examples_by_technique(technique_id: str, domain: str = "enterprise") -> list[dict]:
    try:
        data = await get_attack_data(domain)
        entries = await _run(data.get_procedure_examples_by_technique, technique_id)
        return _relationship_list(entries)
    except Exception as exc:
        logger.debug("get_procedure_examples_by_technique(%s): %s", technique_id, exc)
        return []


async def get_techniques_used_by_campaign(campaign_id: str, domain: str = "enterprise") -> list[dict]:
    try:
        data = await get_attack_data(domain)
        entries = await _run(data.get_techniques_used_by_campaign, campaign_id)
        return _relationship_list(entries)
    except Exception as exc:
        logger.debug("get_techniques_used_by_campaign(%s): %s", campaign_id, exc)
        return []


async def get_campaigns_using_technique(technique_id: str, domain: str = "enterprise") -> list[dict]:
    try:
        data = await get_attack_data(domain)
        entries = await _run(data.get_campaigns_using_technique, technique_id)
        return _relationship_list(entries)
    except Exception as exc:
        logger.debug("get_campaigns_using_technique(%s): %s", technique_id, exc)
        return []


async def get_techniques_mitigated_by_mitigation(mitigation_id: str, domain: str = "enterprise") -> list[dict]:
    try:
        data = await get_attack_data(domain)
        entries = await _run(data.get_techniques_mitigated_by_mitigation, mitigation_id)
        return _relationship_list(entries)
    except Exception as exc:
        logger.debug("get_techniques_mitigated_by_mitigation(%s): %s", mitigation_id, exc)
        return []


async def get_objects_created_after(date: str, domain: str = "enterprise") -> list[dict]:
    """date: 'YYYY-MM-DD'"""
    try:
        from dateutil import parser as dateparser

        data = await get_attack_data(domain)
        dt = dateparser.parse(date)
        items = await _run(data.get_objects_created_after, dt)
        return _safe_list(items)
    except Exception as exc:
        logger.debug("get_objects_created_after(%s): %s", date, exc)
        return []


async def get_objects_modified_after(date: str, domain: str = "enterprise") -> list[dict]:
    """date: 'YYYY-MM-DD'"""
    try:
        from dateutil import parser as dateparser

        data = await get_attack_data(domain)
        dt = dateparser.parse(date)
        items = await _run(data.get_objects_modified_after, dt)
        return _safe_list(items)
    except Exception as exc:
        logger.debug("get_objects_modified_after(%s): %s", date, exc)
        return []


async def get_revoked_techniques(domain: str = "enterprise") -> list[dict]:
    try:
        data = await get_attack_data(domain)
        all_techs = await _run(data.get_techniques, include_subtechniques=True, remove_revoked_deprecated=False)
        revoked = [t for t in (all_techs or []) if getattr(t, "revoked", False)]
        return _safe_list(revoked, True)
    except Exception as exc:
        logger.debug("get_revoked_techniques: %s", exc)
        return []


async def get_groups_by_alias(alias: str, domain: str = "enterprise") -> list[dict]:
    try:
        data = await get_attack_data(domain)
        items = await _run(data.get_groups_by_alias, alias)
        return _safe_list(items)
    except Exception as exc:
        logger.debug("get_groups_by_alias(%s): %s", alias, exc)
        return []


async def get_software_by_alias(alias: str, domain: str = "enterprise") -> list[dict]:
    try:
        data = await get_attack_data(domain)
        items = await _run(data.get_software_by_alias, alias)
        return _safe_list(items)
    except Exception as exc:
        logger.debug("get_software_by_alias(%s): %s", alias, exc)
        return []


def get_loaded_domains() -> list[str]:
    return list(_instances.keys())


def get_data_dir() -> str:
    return str(_get_data_dir())
