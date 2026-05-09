-- Non-English CTI Pipeline: Database Schema
-- Run against: non_english_cti database

-- Sources table
CREATE TABLE IF NOT EXISTS sources (
    source_id UUID PRIMARY KEY,
    source_name VARCHAR(255) NOT NULL,
    url TEXT NOT NULL,
    country VARCHAR(5),
    region VARCHAR(100),
    language VARCHAR(5),
    source_type VARCHAR(50),
    collection_method VARCHAR(50),
    authentication VARCHAR(50) DEFAULT 'none',
    update_frequency VARCHAR(50),
    intelligence_value SMALLINT DEFAULT 3,
    reliability SMALLINT DEFAULT 3,
    legal_ethical_risk SMALLINT DEFAULT 1,
    collection_priority SMALLINT DEFAULT 3,
    enabled BOOLEAN DEFAULT TRUE,
    notes TEXT,
    last_fetched_at TIMESTAMPTZ,
    last_error TEXT,
    consecutive_failures SMALLINT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- CTI records table
CREATE TABLE IF NOT EXISTS cti_records (
    record_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id UUID REFERENCES sources(source_id),
    source_url TEXT,
    canonical_url TEXT,
    title_original TEXT,
    title_en TEXT,
    body_original TEXT,
    body_en TEXT,
    language_detected VARCHAR(5),
    country VARCHAR(5),
    region VARCHAR(100),
    source_type VARCHAR(50),
    published_at TIMESTAMPTZ,
    collected_at TIMESTAMPTZ DEFAULT NOW(),
    translation_method VARCHAR(50),
    translation_confidence FLOAT DEFAULT 0.0,
    confidence_score FLOAT DEFAULT 0.0,
    reliability_score FLOAT DEFAULT 0.0,
    hash_content VARCHAR(64),
    analyst_status VARCHAR(20) DEFAULT 'new',
    analyst_notes TEXT,
    reviewed_at TIMESTAMPTZ,
    reviewed_by VARCHAR(100),
    tags TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Extracted IOCs table
CREATE TABLE IF NOT EXISTS extracted_iocs (
    ioc_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    record_id UUID REFERENCES cti_records(record_id) ON DELETE CASCADE,
    ioc_type VARCHAR(50) NOT NULL,
    ioc_value TEXT NOT NULL,
    context TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Extracted CVEs table
CREATE TABLE IF NOT EXISTS extracted_cves (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    record_id UUID REFERENCES cti_records(record_id) ON DELETE CASCADE,
    cve_id VARCHAR(20) NOT NULL,
    nvd_description TEXT,
    cvss_score FLOAT,
    cvss_version VARCHAR(5),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Extracted TTPs table
CREATE TABLE IF NOT EXISTS extracted_ttps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    record_id UUID REFERENCES cti_records(record_id) ON DELETE CASCADE,
    technique_id VARCHAR(20) NOT NULL,
    technique_name VARCHAR(255),
    confidence FLOAT DEFAULT 0.5,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Extracted actors table
CREATE TABLE IF NOT EXISTS extracted_actors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    record_id UUID REFERENCES cti_records(record_id) ON DELETE CASCADE,
    actor_name VARCHAR(255) NOT NULL,
    actor_name_en VARCHAR(255),
    confidence FLOAT DEFAULT 0.5,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Extracted malware table
CREATE TABLE IF NOT EXISTS extracted_malware (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    record_id UUID REFERENCES cti_records(record_id) ON DELETE CASCADE,
    malware_name VARCHAR(255) NOT NULL,
    is_family BOOLEAN DEFAULT TRUE,
    confidence FLOAT DEFAULT 0.5,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50),
    entity_id UUID,
    details JSONB,
    performed_by VARCHAR(100) DEFAULT 'system',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_records_source ON cti_records(source_id);
CREATE INDEX IF NOT EXISTS idx_records_language ON cti_records(language_detected);
CREATE INDEX IF NOT EXISTS idx_records_status ON cti_records(analyst_status);
CREATE INDEX IF NOT EXISTS idx_records_collected ON cti_records(collected_at DESC);
CREATE INDEX IF NOT EXISTS idx_records_confidence ON cti_records(confidence_score DESC);
CREATE INDEX IF NOT EXISTS idx_records_hash ON cti_records(hash_content);
CREATE INDEX IF NOT EXISTS idx_iocs_record ON extracted_iocs(record_id);
CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON extracted_iocs(ioc_type, ioc_value);
CREATE INDEX IF NOT EXISTS idx_cves_record ON extracted_cves(record_id);
CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON extracted_cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_ttps_record ON extracted_ttps(record_id);
CREATE INDEX IF NOT EXISTS idx_actors_record ON extracted_actors(record_id);
CREATE INDEX IF NOT EXISTS idx_malware_record ON extracted_malware(record_id);
CREATE INDEX IF NOT EXISTS idx_sources_enabled ON sources(enabled);
CREATE INDEX IF NOT EXISTS idx_sources_priority ON sources(collection_priority);
