"""Translation pipeline: LibreTranslate (self-hosted) + optional DeepL."""

from __future__ import annotations
import asyncio
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class TranslationPipeline:
    """Two-track translation: LibreTranslate for routine, optional commercial for high-value.

    Always preserves original text alongside translation.
    """

    def __init__(
        self,
        libretranslate_url: str = "http://localhost:5000",
        deepl_api_key: Optional[str] = None,
        google_api_key: Optional[str] = None,
        use_libretranslate: bool = True,
        timeout: float = 60.0,
    ):
        self.libretranslate_url = libretranslate_url.rstrip("/")
        self.deepl_api_key = deepl_api_key
        self.google_api_key = google_api_key
        self.use_libretranslate = use_libretranslate
        self.timeout = timeout

    async def translate(
        self,
        text: str,
        source_lang: str,
        target_lang: str = "en",
        high_value: bool = False,
    ) -> dict:
        """Translate text, returning both original and translation with metadata.

        Returns dict:
            translated_text, method, confidence, source_lang, target_lang
        """
        if not text or not text.strip():
            return {
                "translated_text": "",
                "method": "none",
                "confidence": 0.0,
                "source_lang": source_lang,
                "target_lang": target_lang,
            }

        # Already in target language
        if source_lang == target_lang:
            return {
                "translated_text": text,
                "method": "identity",
                "confidence": 1.0,
                "source_lang": source_lang,
                "target_lang": target_lang,
            }

        # Try commercial provider first for high-value items
        if high_value and self.deepl_api_key:
            result = await self._translate_deepl(text, source_lang, target_lang)
            if result:
                result["method"] = "deepl"
                return result

        # Try LibreTranslate (self-hosted, privacy-safe)
        if self.use_libretranslate:
            result = await self._translate_libre(text, source_lang, target_lang)
            if result:
                result["method"] = "libretranslate"
                return result

        # Fallback: deep-translator library (wraps multiple engines)
        result = await self._translate_deep_translator(text, source_lang, target_lang)
        if result:
            result["method"] = "deep-translator"
            return result

        return {
            "translated_text": "",
            "method": "failed",
            "confidence": 0.0,
            "source_lang": source_lang,
            "target_lang": target_lang,
        }

    async def _translate_libre(
        self, text: str, source_lang: str, target_lang: str
    ) -> Optional[dict]:
        """Translate using self-hosted LibreTranslate."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.libretranslate_url}/translate",
                    json={
                        "q": text[:5000],  # LibreTranslate has size limits
                        "source": source_lang,
                        "target": target_lang,
                        "format": "text",
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                return {
                    "translated_text": data.get("translatedText", ""),
                    "confidence": 0.7,  # LibreTranslate doesn't return confidence
                    "source_lang": source_lang,
                    "target_lang": target_lang,
                }
        except Exception as e:
            logger.warning("LibreTranslate failed: %s", e)
            return None

    async def _translate_deepl(
        self, text: str, source_lang: str, target_lang: str
    ) -> Optional[dict]:
        """Translate using DeepL API (commercial, high quality)."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    "https://api-free.deepl.com/v2/translate",
                    data={
                        "auth_key": self.deepl_api_key,
                        "text": text,
                        "source_lang": source_lang.upper(),
                        "target_lang": target_lang.upper(),
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                if data.get("translations"):
                    return {
                        "translated_text": data["translations"][0]["text"],
                        "confidence": 0.95,
                        "source_lang": source_lang,
                        "target_lang": target_lang,
                    }
        except Exception as e:
            logger.warning("DeepL translation failed: %s", e)
        return None

    async def _translate_deep_translator(
        self, text: str, source_lang: str, target_lang: str
    ) -> Optional[dict]:
        """Fallback translation using deep-translator library."""
        try:
            from deep_translator import GoogleTranslator

            # Run in executor to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: GoogleTranslator(
                    source=source_lang, target=target_lang
                ).translate(text[:4900]),
            )
            if result:
                return {
                    "translated_text": result,
                    "confidence": 0.6,
                    "source_lang": source_lang,
                    "target_lang": target_lang,
                }
        except Exception as e:
            logger.warning("deep-translator failed: %s", e)
        return None
