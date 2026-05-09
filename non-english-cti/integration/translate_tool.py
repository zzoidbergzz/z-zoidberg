"""MCP tool: translate text between languages using LibreTranslate."""

from __future__ import annotations

import httpx
import structlog

from app.mcp.registry import register_tool

logger = structlog.get_logger(__name__)

LT_URL = "http://localhost:5000"


async def _translate_text(args: dict, db, auth) -> dict:
    text = (args.get("text") or "").strip()
    if not text:
        return {"error": "text is required"}

    source_lang = args.get("source_lang", "auto")
    target_lang = args.get("target_lang", "en")
    detect_only = args.get("detect_only", False)

    # If detect-only, just return the language
    if detect_only:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"{LT_URL}/detect",
                    data={"q": text[:1000]},
                )
                if resp.is_success:
                    detections = resp.json()
                    if detections:
                        return {
                            "detected_language": detections[0]["language"],
                            "confidence": detections[0]["confidence"],
                        }
        except Exception as exc:
            logger.warning("lt_detect_error", error=str(exc))
        return {"error": "language_detection_failed"}

    # Translate
    payload = {
        "q": text[:5000],
        "source": source_lang if source_lang != "auto" else "auto",
        "target": target_lang,
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(f"{LT_URL}/translate", data=payload)
            if resp.is_success:
                result = resp.json()
                return {
                    "translated_text": result.get("translatedText", ""),
                    "source_language": source_lang,
                    "target_language": target_lang,
                    "method": "libretranslate",
                }
            else:
                return {"error": "translation_failed", "detail": resp.text[:200]}
    except httpx.ConnectError:
        return {"error": "libretranslate_unavailable", "message": "LibreTranslate service not running on port 5000"}
    except Exception as exc:
        logger.warning("lt_translate_error", error=str(exc))
        return {"error": "translation_error", "detail": str(exc)}


register_tool(
    name="translate_text",
    fn=_translate_text,
    schema={
        "type": "object",
        "required": ["text"],
        "properties": {
            "text": {"type": "string", "description": "Text to translate (max 5000 chars)"},
            "source_lang": {"type": "string", "description": "Source language code (e.g. fr, de, zh, ru, auto)"},
            "target_lang": {"type": "string", "description": "Target language code (default: en)"},
            "detect_only": {"type": "boolean", "description": "Only detect language, don't translate"},
        },
    },
    description="Translate text between languages using the self-hosted LibreTranslate service. Supports 19 languages including zh, ru, ko, ja, fr, de, es, ar, fa, uk, vi. Use detect_only=true to just identify the language.",
    scope="read",
)
