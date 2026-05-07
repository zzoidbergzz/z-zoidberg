from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Core
    DATABASE_URL: str = "postgresql+asyncpg://sk:sk@localhost/sk"
    REDIS_URL: str = "redis://localhost:6379"
    SECRET_KEY: str = "change-me-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Enrichment providers
    VIRUSTOTAL_API_KEY: str = ""
    SHODAN_API_KEY: str = ""
    IPINFO_TOKEN: str = ""
    GREYNOISE_API_KEY: str = ""
    CROWDSTRIKE_CLIENT_ID: str = ""
    CROWDSTRIKE_CLIENT_SECRET: str = ""
    CROWDSTRIKE_BASE_URL: str = "https://api.crowdstrike.com"

    # OpenCTI
    OPENCTI_URL: str = ""
    OPENCTI_TOKEN: str = ""
    OPENCTI_VERIFY_SSL: bool = True
    OPENCTI_SYNC_INTERVAL_SECONDS: int = 3600
    OPENCTI_PUSH_ENABLED: bool = False

    # MISP
    MISP_URL: str = ""
    MISP_KEY: str = ""
    MISP_VERIFY_SSL: bool = True

    # LLM
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    EMBEDDING_PROVIDER: str = "openai"
    EMBEDDING_MODEL: str = "text-embedding-3-small"
    EMBEDDING_DIMENSION: int = 1536

    # Observability
    OTEL_EXPORTER_OTLP_ENDPOINT: str = ""
    LOG_LEVEL: str = "INFO"

    # SMTP
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""

    # Slack
    SLACK_WEBHOOK_URL: str = ""

    # Budgets
    VIRUSTOTAL_DAILY_BUDGET: int = 500
    SHODAN_DAILY_BUDGET: int = 100
    IPINFO_MONTHLY_BUDGET: int = 50000
    GREYNOISE_DAILY_BUDGET: int = 1000
    CROWDSTRIKE_DAILY_BUDGET: int = 1000

    # TTLs (seconds)
    ENRICHMENT_TTL_VIRUSTOTAL: int = 86400
    ENRICHMENT_TTL_SHODAN: int = 3600
    ENRICHMENT_TTL_IPINFO: int = 86400
    ENRICHMENT_TTL_GREYNOISE: int = 3600
    ENRICHMENT_TTL_CROWDSTRIKE: int = 3600

    # NVD
    NVD_API_KEY: str = ""
    NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # GitHub
    GITHUB_TOKEN: str = ""
    GITHUB_BASE_URL: str = "https://api.github.com"

    # KEV / EUVD
    KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EUVD_BASE_URL: str = "https://euvdservices.enisa.europa.eu/api"

    # MISP compat alias
    MISP_VERIFYCERT: bool = True

    # Embeddings
    EMBEDDING_API_URL: str = ""
    EMBEDDING_API_KEY: str = ""
    EMBEDDING_DIM: int = 1536

    # LLM
    LLM_BASE_URL: str = ""
    LLM_API_KEY: str = ""

    # Observability
    SERVICE_NAME: str = "security-knowledge"
    LOG_FORMAT: str = "json"

    # Ghidra
    GHIDRA_SERVER_URL: str = ""

    # BYOK
    BYOK_ENCRYPTION_KEY: str = ""

    # Playwright
    PLAYWRIGHT_ENABLED: bool = False
    PLAYWRIGHT_TIMEOUT_MS: int = 30000

    # Sectors / ISACs
    DEFAULT_SECTOR: str = "uk-general"
    SECTOR_INVITE_EXPIRY_DAYS: int = 7


settings = Settings()
