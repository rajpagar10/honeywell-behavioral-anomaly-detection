"""Cross-cutting HTTP middleware."""

import logging
from collections.abc import Awaitable, Callable
from time import perf_counter
from uuid import UUID, uuid4

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

_LOGGER = logging.getLogger(__name__)
_CORRELATION_HEADER = "X-Correlation-ID"


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Attach a validated correlation identifier to every request and response."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Log request completion and return the correlation identifier."""

        correlation_id = _parse_correlation_id(request.headers.get(_CORRELATION_HEADER))
        request.state.correlation_id = correlation_id
        started = perf_counter()
        response = await call_next(request)
        response.headers[_CORRELATION_HEADER] = str(correlation_id)
        _LOGGER.info(
            "request completed method=%s path=%s status=%s duration_ms=%.2f",
            request.method,
            request.url.path,
            response.status_code,
            (perf_counter() - started) * 1000,
            extra={"correlation_id": correlation_id},
        )
        return response


def _parse_correlation_id(value: str | None) -> UUID:
    """Use a valid client identifier or create a new one."""

    if value is None:
        return uuid4()
    try:
        return UUID(value)
    except ValueError:
        return uuid4()
