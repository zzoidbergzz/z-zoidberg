from app.config import settings

try:
    from pymisp import ExpandedPyMISP
    HAS_PYMISP = True
except ImportError:
    HAS_PYMISP = False


class MISPClient:
    def __init__(self):
        self._misp = None
        if HAS_PYMISP and settings.MISP_URL and settings.MISP_KEY:
            self._misp = ExpandedPyMISP(settings.MISP_URL, settings.MISP_KEY, ssl=settings.MISP_VERIFYCERT)

    def get_recent_events(self, limit: int = 100) -> list[dict]:
        if not self._misp:
            return []
        events = self._misp.search(limit=limit, pythonify=True)
        return [{"id": e.id, "info": e.info, "date": e.date} for e in events]
