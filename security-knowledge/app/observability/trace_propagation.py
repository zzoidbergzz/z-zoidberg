"""OTel trace context propagation helpers for ARQ background jobs.

Problem: ARQ jobs run in a separate process/coroutine from the HTTP request
that enqueued them. The OTel span that was active during enqueue is not
automatically available inside the job.

Solution (W3C TraceContext):
  - On enqueue: inject current span context into a dict via
    opentelemetry.propagate.inject() → pass dict as job kwarg `_otel_ctx`
  - On job start: extract from `_otel_ctx` via propagate.extract() →
    create a new span as a remote child, store in ARQ ctx

Usage in job functions:
    async def my_job(ctx, some_arg: str, _otel_ctx: dict | None = None):
        with trace_from_job(ctx, "my_job", _otel_ctx) as span:
            span.set_attribute("some_arg", some_arg)
            ...

Usage when enqueueing:
    await pool.enqueue_job("my_job", some_arg, _otel_ctx=get_traceparent())
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Generator

import structlog
from opentelemetry import propagate, trace
from opentelemetry.context import Context
from opentelemetry.trace import NonRecordingSpan, Span, SpanKind

logger = structlog.get_logger(__name__)
_tracer = trace.get_tracer("security-knowledge.worker")


def get_traceparent() -> dict[str, str]:
    """Extract current OTel context into a W3C-propagation dict.

    Call this in the HTTP handler *before* enqueuing the ARQ job so the
    active request span becomes the parent of the worker span.

    Returns a dict like {"traceparent": "00-<trace_id>-<span_id>-01"}
    or an empty dict when tracing is not configured.
    """
    carrier: dict[str, str] = {}
    propagate.inject(carrier)
    return carrier


def extract_context(carrier: dict[str, str] | None) -> Context:
    """Reconstruct an OTel Context from a propagation carrier dict."""
    if not carrier:
        return Context()
    return propagate.extract(carrier)


@contextmanager
def trace_from_job(
    ctx: dict[str, Any],
    operation_name: str,
    otel_carrier: dict[str, str] | None = None,
    attributes: dict[str, Any] | None = None,
) -> Generator[Span, None, None]:
    """Context manager that starts a span linked to the enqueue-time trace.

    The job span is created as a CONSUMER span (SpanKind.CONSUMER) with the
    HTTP request span as its remote parent — this correctly models the
    producer/consumer relationship in distributed tracing.

    Args:
        ctx: ARQ context dict (used for job_id logging)
        operation_name: Name for the new span
        otel_carrier: The `_otel_ctx` kwarg passed from the enqueue site
        attributes: Extra span attributes to set on creation
    """
    parent_context = extract_context(otel_carrier)
    job_id = ctx.get("job_id", "unknown")

    with _tracer.start_as_current_span(
        operation_name,
        context=parent_context,
        kind=SpanKind.CONSUMER,
        attributes={
            "messaging.system": "arq",
            "messaging.operation": "process",
            "job.id": str(job_id),
            **(attributes or {}),
        },
    ) as span:
        logger.info(
            "worker_span_started",
            operation=operation_name,
            job_id=str(job_id),
            trace_id=format(span.get_span_context().trace_id, "032x")
            if not isinstance(span, NonRecordingSpan)
            else "no-op",
        )
        try:
            yield span
        except Exception as exc:
            span.record_exception(exc)
            span.set_status(trace.StatusCode.ERROR, str(exc))
            raise
        finally:
            logger.info("worker_span_ended", operation=operation_name, job_id=str(job_id))
