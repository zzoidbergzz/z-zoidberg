from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response

http_requests_total = Counter("http_requests_total", "Total HTTP requests", ["method", "path", "status"])
http_request_duration_seconds = Histogram("http_request_duration_seconds", "HTTP request duration", ["method", "path"])
active_requests = Gauge("active_requests", "Active HTTP requests")
enrichment_calls_total = Counter("enrichment_calls_total", "Enrichment provider calls", ["provider", "status"])
ingestion_jobs_total = Counter("ingestion_jobs_total", "Ingestion jobs", ["status"])
vector_search_duration_seconds = Histogram("vector_search_duration_seconds", "Vector search duration")


def metrics_response() -> Response:
    data = generate_latest()
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)
