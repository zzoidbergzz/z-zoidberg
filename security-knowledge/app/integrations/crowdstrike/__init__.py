"""CrowdStrike Falcon integration — Intel, IOC, and Spotlight feeds.

Uses the CrowdStrike OAuth2 API directly (falconpy SDK patterns).
Credentials are read from ``settings.CROWDSTRIKE_CLIENT_ID`` and
``settings.CROWDSTRIKE_CLIENT_SECRET``.
"""
from app.integrations.crowdstrike.client import FalconClient
from app.integrations.crowdstrike.normalizer import normalize_actor, normalize_indicator, normalize_report

__all__ = ["FalconClient", "normalize_actor", "normalize_indicator", "normalize_report"]
