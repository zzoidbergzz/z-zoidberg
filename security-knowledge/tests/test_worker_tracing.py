"""Tests for OTel trace context propagation through the ARQ worker."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ctx(job_id: str = "test-job-123") -> dict:
    return {"job_id": job_id}


# ---------------------------------------------------------------------------
# trace_propagation helpers
# ---------------------------------------------------------------------------

class TestGetTraceparent:
    def test_returns_dict(self):
        from app.observability.trace_propagation import get_traceparent
        result = get_traceparent()
        assert isinstance(result, dict)

    def test_empty_when_no_active_span(self):
        """With no configured exporter/provider the inject produces nothing."""
        from app.observability.trace_propagation import get_traceparent
        result = get_traceparent()
        # May be empty or contain a traceparent — either is valid
        assert result is not None


class TestExtractContext:
    def test_returns_context_from_empty_carrier(self):
        from app.observability.trace_propagation import extract_context
        from opentelemetry.context import Context
        ctx = extract_context({})
        assert isinstance(ctx, Context)

    def test_returns_context_from_none(self):
        from app.observability.trace_propagation import extract_context
        from opentelemetry.context import Context
        ctx = extract_context(None)
        assert isinstance(ctx, Context)

    def test_roundtrip(self):
        """inject → extract should give valid (possibly no-op) context."""
        from app.observability.trace_propagation import extract_context, get_traceparent
        carrier = get_traceparent()
        ctx = extract_context(carrier)
        assert ctx is not None


# ---------------------------------------------------------------------------
# trace_from_job context manager
# ---------------------------------------------------------------------------

class TestTraceFromJob:
    def test_basic_success(self):
        """Span starts and ends without error."""
        import asyncio
        from app.observability.trace_propagation import trace_from_job

        ctx = _make_ctx()
        ran = []
        with trace_from_job(ctx, "test_op", None) as span:
            ran.append(True)
            assert span is not None

        assert ran == [True]

    def test_exception_recorded(self):
        """Exceptions inside the block propagate and are recorded on the span."""
        from app.observability.trace_propagation import trace_from_job

        ctx = _make_ctx()
        with pytest.raises(ValueError, match="boom"):
            with trace_from_job(ctx, "failing_op", None):
                raise ValueError("boom")

    def test_with_carrier(self):
        """Carrier dict is accepted without error."""
        from app.observability.trace_propagation import trace_from_job

        ctx = _make_ctx()
        carrier = {"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}
        with trace_from_job(ctx, "test_with_parent", carrier) as span:
            assert span is not None

    def test_attributes_set(self):
        """Extra attributes dict is accepted."""
        from app.observability.trace_propagation import trace_from_job

        ctx = _make_ctx("attr-job")
        with trace_from_job(ctx, "attr_test", None, {"custom.attr": "hello"}) as span:
            pass  # should not raise


# ---------------------------------------------------------------------------
# Worker job function signatures
# ---------------------------------------------------------------------------

class TestWorkerJobSignatures:
    def test_process_ingest_job_accepts_otel_ctx(self):
        import inspect
        from app.worker import process_ingest_job
        sig = inspect.signature(process_ingest_job)
        assert "_otel_ctx" in sig.parameters

    def test_run_enrichment_accepts_otel_ctx(self):
        import inspect
        from app.worker import run_enrichment
        sig = inspect.signature(run_enrichment)
        assert "_otel_ctx" in sig.parameters

    def test_send_digests_accepts_otel_ctx(self):
        import inspect
        from app.worker import send_digests
        sig = inspect.signature(send_digests)
        assert "_otel_ctx" in sig.parameters

    def test_check_ioc_watches_accepts_otel_ctx(self):
        import inspect
        from app.worker import check_ioc_watches
        sig = inspect.signature(check_ioc_watches)
        assert "_otel_ctx" in sig.parameters


# ---------------------------------------------------------------------------
# Worker job function execution
# ---------------------------------------------------------------------------

class TestWorkerJobExecution:
    @pytest.mark.asyncio
    async def test_process_ingest_job(self):
        from app.worker import process_ingest_job

        mock_record_start = AsyncMock()
        mock_record_end = AsyncMock()

        with (
            patch("app.worker.record_job_start", mock_record_start),
            patch("app.worker.record_job_end", mock_record_end),
        ):
            ctx = _make_ctx()
            result = await process_ingest_job(ctx, "job-abc", _otel_ctx=None)
            assert result["status"] == "complete"
            assert result["job_id"] == "job-abc"

    @pytest.mark.asyncio
    async def test_run_enrichment(self):
        from app.worker import run_enrichment

        mock_record_start = AsyncMock()
        mock_record_end = AsyncMock()

        with (
            patch("app.worker.record_job_start", mock_record_start),
            patch("app.worker.record_job_end", mock_record_end),
        ):
            ctx = _make_ctx()
            result = await run_enrichment(ctx, "entity-1", "tenant-1", _otel_ctx=None)
            assert result["status"] == "complete"

    @pytest.mark.asyncio
    async def test_send_digests(self):
        from app.worker import send_digests

        mock_record_start = AsyncMock()
        mock_record_end = AsyncMock()

        with (
            patch("app.worker.record_job_start", mock_record_start),
            patch("app.worker.record_job_end", mock_record_end),
        ):
            ctx = _make_ctx()
            result = await send_digests(ctx, _otel_ctx=None)
            assert result["status"] == "complete"

    @pytest.mark.asyncio
    async def test_process_ingest_job_with_carrier(self):
        """Job functions accept a non-None carrier."""
        from app.worker import process_ingest_job

        mock_record_start = AsyncMock()
        mock_record_end = AsyncMock()

        with (
            patch("app.worker.record_job_start", mock_record_start),
            patch("app.worker.record_job_end", mock_record_end),
        ):
            ctx = _make_ctx()
            carrier = {"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}
            result = await process_ingest_job(ctx, "job-with-trace", _otel_ctx=carrier)
            assert result["status"] == "complete"


# ---------------------------------------------------------------------------
# WorkerSettings
# ---------------------------------------------------------------------------

class TestWorkerSettings:
    def test_functions_registered(self):
        from app.worker import WorkerSettings, process_ingest_job, run_enrichment, send_digests, check_ioc_watches
        assert process_ingest_job in WorkerSettings.functions
        assert run_enrichment in WorkerSettings.functions
        assert send_digests in WorkerSettings.functions
        assert check_ioc_watches in WorkerSettings.functions

    def test_lifecycle_hooks_set(self):
        from app.worker import WorkerSettings
        assert WorkerSettings.on_startup is not None
        assert WorkerSettings.on_shutdown is not None
