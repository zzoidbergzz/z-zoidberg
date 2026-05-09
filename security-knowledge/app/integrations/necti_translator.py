"""Auto-translation helper for the SK platform.

Call translate_if_needed() on any text that might be non-English.
Uses LibreTranslate on localhost:5000 (installed alongside the necti pipeline).

Usage in ingest workers:
    from app.integrations.necti_translator import translate_if_needed
    
    result = await translate_if_needed(title, source_hint="fr")
    english_title = result["translated_text"]  # or original if already English
"""

from __future__ import annotations

import httpx
import structlog

logger = structlog.get_logger(__name__)

LT_URL = "http://localhost:5000"
LT_TIMEOUT = 30.0
MAX_TEXT_LEN = 5000


async def detect_language(text: str) -> tuple[str, float]:
    """Detect language of text. Returns (code, confidence)."""
    if not text or len(text) < 20:
        return ("en", 0.0)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(f"{LT_URL}/detect", data={"q": text[:1000]})
            if resp.is_success:
                results = resp.json()
                if results:
                    return (results[0]["language"], results[0]["confidence"])
    except Exception as exc:
        logger.debug("lt_detect_error", error=str(exc))
    return ("unknown", 0.0)


async def translate_if_needed(
    text: str,
    source_hint: str = "",
    target: str = "en",
) -> dict:
    """Translate text if it's not English. Returns dict with keys:
    - translated_text: English text (translated or original)
    - original_text: the input text
    - source_language: detected or hinted language
    - was_translated: bool
    - method: "libretranslate" | "identity" | "detection_failed"
    """
    if not text:
        return {
            "translated_text": text,
            "original_text": text,
            "source_language": source_hint or "unknown",
            "was_translated": False,
            "method": "empty",
        }

    # Detect or use hint
    if source_hint and source_hint != "auto":
        lang = source_hint
    else:
        lang, conf = await detect_language(text)
        if lang == "en" or lang == "unknown":
            return {
                "translated_text": text,
                "original_text": text,
                "source_language": lang,
                "was_translated": False,
                "method": "identity" if lang == "en" else "detection_failed",
            }

    if lang == "en":
        return {
            "translated_text": text,
            "original_text": text,
            "source_language": "en",
            "was_translated": False,
            "method": "identity",
        }

    # Translate
    try:
        async with httpx.AsyncClient(timeout=LT_TIMEOUT) as client:
            resp = await client.post(
                f"{LT_URL}/translate",
                data={"q": text[:MAX_TEXT_LEN], "source": lang, "target": target},
            )
            if resp.is_success:
                result = resp.json()
                return {
                    "translated_text": result.get("translatedText", text),
                    "original_text": text,
                    "source_language": lang,
                    "was_translated": True,
                    "method": "libretranslate",
                }
    except httpx.ConnectError:
        logger.warning("lt_unavailable", msg="LibreTranslate not running, skipping translation")
    except Exception as exc:
        logger.warning("lt_translate_error", error=str(exc))

    # Fallback: return original
    return {
        "translated_text": text,
        "original_text": text,
        "source_language": lang,
        "was_translated": False,
        "method": "fallback",
    }


async def translate_batch(
    texts: list[str],
    source_hint: str = "",
    target: str = "en",
) -> list[dict]:
    """Translate a batch of texts. Returns list of result dicts."""
    return [await translate_if_needed(t, source_hint, target) for t in texts]
