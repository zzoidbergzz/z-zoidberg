# Analyst Guide: Non-English CTI Review

## Overview
This pipeline collects cyber threat intelligence from non-English sources, translates it, and presents it for your review. You see both the original text and the English translation.

## Review Queue

### Item States
| State | Meaning |
|-------|---------|
| **New** | Fresh item, not yet reviewed |
| **In Review** | Currently being reviewed |
| **Approved** | Verified, ready for CTI platform export |
| **Rejected** | Not actionable, discard |

### Priority Review Items
The following items **always** require human review before export:
- **Actor attribution** — any named threat actor
- **Victim claims** — any named organisation as a victim
- **Exploit-in-the-wild** — assertions of active exploitation
- **Low confidence** — items with confidence score < 0.3

## Reviewing a Record

### Side-by-Side View
- **Left**: Original language text (preserved exactly as collected)
- **Right**: English machine translation
- **Below**: Extracted IOCs, CVEs, TTPs, actors, malware

### What to Check
1. **Translation accuracy** — Does the translation capture the meaning?
2. **Proper nouns** — Are actor names, product names, organisation names correct?
3. **IOCs** — Are extracted IOCs actually indicators? (Not just any IP/domain)
4. **Actor names** — Is the attribution supported by the source?
5. **Victim names** — Is the source reliable enough for victim claims?

### Common Translation Issues
| Language | Issue | Example |
|----------|-------|---------|
| Chinese | Actor code names differ | "海莲花" = OceanLotus |
| Russian | Cybercrime slang | "кардинг" = carding |
| Korean | DPRK-specific terms | "북한 해커" = North Korean hacker |
| Japanese | Product names | "脆弱性" = vulnerability |
| Arabic | RTL text rendering | Check character order |

### Expand Original
Click "Expand Original" to see the full original-language article. This lets you:
- Challenge the translation
- Find context the translator missed
- Verify proper nouns and technical terms
- Check for information lost in translation

## Scoring

### Confidence Score (0-1)
Automated score based on:
- Source reliability (40%)
- Translation quality (30%)
- Extraction quality (30%)

### Source Reliability (0-1)
Based on source type:
- CERT/government: ~0.9
- Vulnerability database: ~0.8
- Security vendor: ~0.7
- News outlet: ~0.5
- Social/forum: ~0.3

## Export

After approval, items are exported to:
- **STIX 2.1** — Standard CTI exchange format
- **MISP** — Event with IOC attributes and tags
- **OpenCTI** — Report with observables and relationships
- **SIEM** — IOC enrichment feeds

## Reporting Translation Errors
If you find a mistranslation:
1. Flag the item
2. Note the correct translation
3. Add to the translation glossary (if a proper noun or recurring term)
4. The glossary is used to improve future translations
