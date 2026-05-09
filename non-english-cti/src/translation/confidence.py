"""Translation confidence scoring and quality assurance."""

from __future__ import annotations
import logging

logger = logging.getLogger(__name__)


class TranslationQA:
    """Quality assurance for machine translations.

    Methods:
    - Back-translation sampling
    - Confidence scoring based on length ratio, script match, keyword preservation
    - Flagging uncertain translations
    """

    # Expected length ratio range (translated / original)
    LENGTH_RATIO_RANGE = (0.5, 2.5)

    # Keywords that should NOT be translated (IOCs, CVEs, actor names)
    PRESERVED_PATTERNS = [
        r"CVE-\d{4}-\d{4,}",
        r"APT-\d+",
        r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",  # IPv4
        r"[a-f0-9]{32,64}",  # hashes
    ]

    def score_translation(
        self,
        original: str,
        translation: str,
        source_lang: str,
        target_lang: str = "en",
    ) -> dict:
        """Score translation quality.

        Returns:
            confidence: 0-1 score
            flags: list of quality issues
            length_ratio: translated/original length ratio
        """
        flags = []
        scores = []

        # 1. Length ratio check
        if original and translation:
            length_ratio = len(translation) / max(len(original), 1)
        else:
            length_ratio = 0.0

        if not (self.LENGTH_RATIO_RANGE[0] <= length_ratio <= self.LENGTH_RATIO_RANGE[1]):
            flags.append(f"abnormal_length_ratio: {length_ratio:.2f}")
            scores.append(0.3)
        else:
            scores.append(0.8)

        # 2. Empty translation check
        if not translation or not translation.strip():
            flags.append("empty_translation")
            return {"confidence": 0.0, "flags": flags, "length_ratio": length_ratio}

        # 3. Script preservation check
        has_cjk = any('\u4e00' <= c <= '\u9fff' for c in original)
        has_cyrillic = any('\u0400' <= c <= '\u04ff' for c in original)
        has_arabic = any('\u0600' <= c <= '\u06ff' for c in original)

        if target_lang == "en":
            # English translation should not contain CJK/Cyrillic/Arabic
            # (except proper nouns, which we allow)
            cjk_in_translation = sum(1 for c in translation if '\u4e00' <= c <= '\u9fff')
            if has_cjk and cjk_in_translation > len(translation) * 0.3:
                flags.append("excessive_cjk_in_en_translation")
                scores.append(0.4)
            else:
                scores.append(0.9)

        # 4. IOC preservation check
        import re
        for pattern in self.PRESERVED_PATTERNS:
            originals = set(re.findall(pattern, original))
            translated = set(re.findall(pattern, translation))
            missing = originals - translated
            if missing:
                flags.append(f"missing_preserved_terms: {missing}")
                scores.append(0.5)

        # 5. Proper noun flagging
        # (Words that look like they should be proper nouns but might be mistranslated)
        original_caps = set(re.findall(r'\b[A-Z][a-z]+(?:\s[A-Z][a-z]+)*\b', original))
        translation_caps = set(re.findall(r'\b[A-Z][a-z]+(?:\s[A-Z][a-z]+)*\b', translation))
        missing_names = original_caps - translation_caps
        if missing_names and len(missing_names) > 2:
            flags.append(f"possible_name_mismatch: {list(missing_names)[:5]}")

        # Calculate overall confidence
        confidence = sum(scores) / max(len(scores), 1)

        return {
            "confidence": round(confidence, 3),
            "flags": flags,
            "length_ratio": round(length_ratio, 3),
        }

    def back_translate_sample(
        self,
        original: str,
        translation: str,
        back_translator,
        source_lang: str,
    ) -> dict:
        """Perform back-translation sampling for high-priority items.

        Returns similarity score between original and back-translated text.
        """
        try:
            # This would call the translation pipeline in reverse
            # For now, return a placeholder
            return {
                "back_translation_available": False,
                "similarity_score": None,
                "note": "Back-translation requires translation pipeline instance",
            }
        except Exception as e:
            logger.warning("Back-translation failed: %s", e)
            return {"back_translation_available": False, "error": str(e)}
