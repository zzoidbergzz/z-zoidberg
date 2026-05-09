# Operational Runbook: Non-English CTI Pipeline

## Quick Start

```bash
# 1. Start infrastructure
cd docker && docker-compose up -d

# 2. Install dependencies
pip install -r requirements.txt

# 3. Validate sources
python scripts/health_check.py catalogue/sources.yaml

# 4. Run collection cycle (priority 1 sources only)
python -m src.scheduler --priority 1

# 5. Full collection
python -m src.scheduler --all
```

## Daily Operations

### Health Check (automated, every 60 min)
- Verify LibreTranslate is responsive
- Check PostgreSQL connectivity
- Validate source RSS feeds return 200
- Flag sources with >5 consecutive failures

### Collection Schedule
| Priority | Interval | Sources |
|----------|----------|---------|
| 1 | 60 min | CERT-FR, BSI, JPCERT, CERT-UA, CNCERT, AhnLab, Kaspersky |
| 2 | 120 min | INCIBE, KrCERT, CERT.pl, Group-IB, 360 Netlab, QiAnXin |
| 3 | 360 min | HTML-only sources, smaller CERTs |
| 4 | Daily | Low-priority sources |

### Translation QA (daily)
- Sample 5% of translations for back-translation quality check
- Flag translations with confidence < 0.5
- Review proper noun translations (actor names, product names)

### Analyst Review Queue
- New items: unreviewed, shown in queue
- Review focus: actor attribution, victim claims, exploit-in-wild
- Side-by-side view: original language + English translation
- Expand original in UI to challenge translation

## Incident Response

### Source Goes Down
1. Check robots.txt / ToS for changes
2. Verify URL hasn't moved
3. Mark source as degraded in registry
4. After 5 consecutive failures, disable source
5. Notify via alert channel

### Translation Quality Drops
1. Check LibreTranslate service health
2. Verify language model availability
3. Fallback to deep-translator (Google)
4. Queue affected items for manual review

### Data Quality Issues
1. False positive IOCs: add to exclusion list
2. Mistranslated actor names: add to glossary
3. Duplicate detection failures: adjust fuzzy threshold

## Maintenance

### Weekly
- Review source health dashboard
- Update source catalogue (new sources, changed URLs)
- Clear old raw HTML/PDF cache (>90 days)
- Verify deduplication is working (check duplicate rate)

### Monthly
- Full translation quality audit
- Source catalogue refresh (FIRST, Trusted Introducer)
- Update MITRE ATT&CK technique patterns
- Review analyst feedback and adjust scoring weights

### Quarterly
- Add new source languages
- Update spaCy models
- Review legal/compliance with new source ToS
- Performance benchmarking and scaling

## Security

### Collection Safeguards
- **NEVER** bypass paywalls or authentication
- **NEVER** download malware samples
- **NEVER** access private/underground sources
- Treat all URLs, documents, and IOCs as potentially malicious
- Fetch through controlled egress environment
- Store raw HTML/PDF safely (no browser rendering)

### Data Handling
- Original text preserved alongside translation
- Translation never overwrites source evidence
- Audit logs for every collected item
- Clear source attribution on all exports
- TLP markings on all shared intelligence

## Troubleshooting

### LibreTranslate Not Starting
```bash
docker logs necti-libretranslate
# Common: models need to download on first start
# Can take 10-30 minutes for all languages
```

### PostgreSQL Connection Issues
```bash
docker logs necti-postgres
# Verify port 5433 is available
# Check credentials in config/pipeline.yaml
```

### RSS Feed Returns Empty
1. Verify feed URL in browser
2. Check if source has changed feed format
3. Try fetching with curl
4. Some feeds may block non-browser user agents
