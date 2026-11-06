"""FastAPI REST API Client for Linux Security Agent.

Provides asynchronous HTTP communication with the central FastAPI backend,
supporting exponential backoff, SSL verification, strict timeouts,
and guaranteed credential secrecy in logging.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from pydantic import BaseModel
import httpx

from agent.config import BackendConfig
from agent.processor.data_formatter import (
    ActionReportPayload,
    HeartbeatPayload,
    TelemetryPayload,
)
from agent.utils.logger import communication_logger


class ApiResponse(BaseModel):
    """Standardized wrapper for HTTP API responses."""

    status_code: int
    is_success: bool
    data: Optional[Any] = None
    error_message: Optional[str] = None


class ApiClient:
    """Asynchronous HTTP client for central backend communication."""

    def __init__(
        self,
        backend_config: BackendConfig,
        agent_id: str,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.config = backend_config
        self.agent_id = agent_id
        self._custom_client = client
        self._client: Optional[httpx.AsyncClient] = client

    def _get_headers(self) -> Dict[str, str]:
        """Constructs request headers including bearer authentication and agent identity."""
        return {
            "Authorization": f"Bearer {self.config.api_key}",
            "X-Agent-ID": self.agent_id,
            "User-Agent": "ai-ids-agent/1.0.0",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _ensure_client(self) -> httpx.AsyncClient:
        """Lazily initializes the underlying httpx AsyncClient."""
        if self._client is None or self._client.is_closed:
            timeout = httpx.Timeout(
                connect=5.0,
                read=self.config.timeout_seconds,
                write=5.0,
                pool=5.0,
            )
            self._client = httpx.AsyncClient(
                base_url=self.config.url,
                headers=self._get_headers(),
                verify=self.config.verify_ssl,
                timeout=timeout,
            )
        return self._client

    async def close(self) -> None:
        """Closes the underlying HTTP client session."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> ApiClient:
        self._ensure_client()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    async def _request_with_retry(
        self,
        method: str,
        path: str,
        json_data: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> ApiResponse:
        """Executes an HTTP request with exponential backoff on transient errors."""
        client = self._ensure_client()
        headers = self._get_headers()
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        max_retries = self.config.max_retries
        backoff = self.config.backoff_factor

        last_error: Optional[str] = None

        for attempt in range(max_retries + 1):
            try:
                response = await client.request(
                    method=method,
                    url=path,
                    json=json_data,
                    headers=headers,
                )

                # HTTP 2xx Success
                if 200 <= response.status_code < 300:
                    try:
                        resp_data = response.json()
                    except Exception:
                        resp_data = {"text": response.text}

                    return ApiResponse(
                        status_code=response.status_code,
                        is_success=True,
                        data=resp_data,
                    )

                # HTTP 4xx Client Error - Do NOT retry (authentication failure, invalid payload)
                if 400 <= response.status_code < 500:
                    err_msg = f"API Client error {response.status_code} on {path}: {response.text[:200]}"
                    communication_logger.error(err_msg)
                    return ApiResponse(
                        status_code=response.status_code,
                        is_success=False,
                        error_message=err_msg,
                    )

                # HTTP 5xx Server Error - Transient, subject to retry
                last_error = f"Backend returned HTTP {response.status_code} for {path}"
                communication_logger.warning(
                    f"{last_error} (attempt {attempt + 1}/{max_retries + 1})"
                )

            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.NetworkError) as exc:
                last_error = f"Network communication error on {path}: {exc.__class__.__name__}"
                communication_logger.warning(
                    f"{last_error} (attempt {attempt + 1}/{max_retries + 1})"
                )
            except Exception as exc:
                last_error = f"Unexpected communication exception on {path}: {exc}"
                communication_logger.error(last_error)
                break

            # If retries remain, back off exponentially
            if attempt < max_retries:
                delay = backoff * (2 ** attempt)
                await asyncio.sleep(delay)

        return ApiResponse(
            status_code=503,
            is_success=False,
            error_message=last_error or "Backend unavailable",
        )

    async def send_telemetry(self, payload: TelemetryPayload | Dict[str, Any]) -> ApiResponse:
        """Sends telemetry features to POST /api/v1/agent/telemetry."""
        data = payload.model_dump(mode="json") if isinstance(payload, TelemetryPayload) else payload
        event_id = data.get("event_id")
        return await self._request_with_retry(
            method="POST",
            path=self.config.endpoints.telemetry,
            json_data=data,
            idempotency_key=event_id,
        )

    async def get_decisions(self) -> ApiResponse:
        """Retrieves mitigation instructions from GET /api/v1/agent/decisions."""
        return await self._request_with_retry(
            method="GET",
            path=self.config.endpoints.decisions,
        )

    async def report_action(self, payload: ActionReportPayload | Dict[str, Any]) -> ApiResponse:
        """Reports firewall mitigation outcome to POST /api/v1/agent/actions/report."""
        data = payload.model_dump(mode="json") if isinstance(payload, ActionReportPayload) else payload
        report_id = data.get("report_id")
        return await self._request_with_retry(
            method="POST",
            path=self.config.endpoints.actions_report,
            json_data=data,
            idempotency_key=report_id,
        )

    async def send_heartbeat(self, payload: HeartbeatPayload | Dict[str, Any]) -> ApiResponse:
        """Sends periodic agent status to POST /api/v1/agent/heartbeat."""
        data = payload.model_dump(mode="json") if isinstance(payload, HeartbeatPayload) else payload
        return await self._request_with_retry(
            method="POST",
            path=self.config.endpoints.heartbeat,
            json_data=data,
        )

