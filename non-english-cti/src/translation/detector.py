"""Language detection using lingua-language-detector."""

from __future__ import annotations
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Minimum text length for reliable detection
MIN_TEXT_LENGTH = 20

# Confidence threshold for detection
CONFIDENCE_THRESHOLD = 0.7


class LanguageDetector:
    """Detect the language of text using lingua-language-detector."""

    def __init__(self, low_memory: bool = True):
        self._detector = None
        self._low_memory = low_memory

    def _init_detector(self):
        """Lazy-load the detector (models are large)."""
        if self._detector is not None:
            return

        try:
            from lingua import Language, LanguageDetectorBuilder

            languages = [
                Language.CHINESE, Language.RUSSIAN, Language.KOREAN,
                Language.JAPANESE, Language.FRENCH, Language.GERMAN,
                Language.SPANISH, Language.PORTUGUESE, Language.POLISH,
                Language.UKRAINIAN, Language.ARABIC, Language.PERSIAN,
                Language.TURKISH, Language.HEBREW, Language.VIETNAMESE,
                Language.THAI, Language.INDONESIAN, Language.HINDI,
                Language.URDU, Language.ITALIAN, Language.DUTCH,
                Language.CZECH, Language.ROMANIAN, Language.HUNGARIAN,
                Language.SLOVAK, Language.FINNISH, Language.SWEDISH,
                Language.ENGLISH,
            ]

            builder = LanguageDetectorBuilder.from_languages(*languages)
            if self._low_memory:
                builder.with_low_accuracy_mode()
            builder.with_minimum_relative_distance(0.1)
            self._detector = builder.build()

            logger.info("Language detector initialised with %d languages", len(languages))
        except ImportError:
            logger.warning("lingua-language-detector not installed, using simple detection")
            self._detector = False  # type: ignore

    def detect(self, text: str) -> tuple[str, float]:
        """Detect language of text. Returns (iso_code, confidence)."""
        self._init_detector()

        if not text or len(text.strip()) < MIN_TEXT_LENGTH:
            return ("", 0.0)

        if self._detector is False:
            return self._simple_detect(text)

        try:
            confidence_values = self._detector.compute_language_confidence_values(text)
            if confidence_values:
                best = confidence_values[0]
                iso_code = best.language.iso_code_639_1.name.lower()
                confidence = best.value
                if confidence >= CONFIDENCE_THRESHOLD:
                    return (iso_code, round(confidence, 3))
                return (iso_code, round(confidence, 3))
        except Exception as e:
            logger.warning("Language detection failed: %s", e)

        return ("", 0.0)

    @staticmethod
    def _simple_detect(text: str) -> tuple[str, float]:
        """Simple language detection based on character ranges."""
        # CJK Unified Ideographs
        chinese_chars = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
        # Hiragana + Katakana
        japanese_chars = sum(1 for c in text if '\u3040' <= c <= '\u30ff')
        # Hangul
        korean_chars = sum(1 for c in text if '\uac00' <= c <= '\ud7af')
        # Cyrillic
        cyrillic_chars = sum(1 for c in text if '\u0400' <= c <= '\u04ff')
        # Arabic
        arabic_chars = sum(1 for c in text if '\u0600' <= c <= '\u06ff')
        # Hebrew
        hebrew_chars = sum(1 for c in text if '\u0590' <= c <= '\u05ff')
        # Thai
        thai_chars = sum(1 for c in text if '\u0e00' <= c <= '\u0e7f')

        total = len(text.strip())
        if total == 0:
            return ("", 0.0)

        scores = {
            "zh": chinese_chars / total,
            "ja": japanese_chars / total,
            "ko": korean_chars / total,
            "ru": cyrillic_chars / total,
            "ar": arabic_chars / total,
            "he": hebrew_chars / total,
            "th": thai_chars / total,
        }

        best = max(scores, key=scores.get)
        if scores[best] > 0.1:
            return (best, round(scores[best], 3))

        return ("en", 0.5)  # Default to English
