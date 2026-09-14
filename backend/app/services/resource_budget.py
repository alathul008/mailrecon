from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from threading import Lock
from typing import Iterator


_current_accounting: ContextVar["ExecutionResourceAccounting | None"] = ContextVar(
    "mailrecon_resource_accounting", default=None
)
_pending_infrastructure_reservations: ContextVar[int] = ContextVar(
    "mailrecon_pending_infrastructure_reservations", default=0
)


class ResourceBudgetExceeded(RuntimeError):
    """A runtime resource budget prevented an outbound operation."""


@dataclass
class ExecutionResourceAccounting:
    """Runtime accounting shared by one execution attempt."""

    budget: "ExecutionResourceBudget"
    external_requests: int = 0
    dns_queries: int = 0
    response_bytes: int = 0
    infrastructure_http_requests: int = 0
    public_web_queries: int = 0
    public_web_results: int = 0
    _lock: Lock = field(default_factory=Lock, repr=False, compare=False)

    def reserve_external_request(self) -> None:
        with self._lock:
            if self.external_requests >= self.budget.max_external_requests:
                raise ResourceBudgetExceeded("Investigation external-request budget exceeded")
            self.external_requests += 1

    def reserve_http_request(self, *, infrastructure: bool = False) -> None:
        with self._lock:
            if self.external_requests >= self.budget.max_external_requests:
                raise ResourceBudgetExceeded("Investigation external-request budget exceeded")
            if infrastructure and self.infrastructure_http_requests >= self.budget.max_infrastructure_http_requests:
                raise ResourceBudgetExceeded("Investigation infrastructure HTTP budget exceeded")
            self.external_requests += 1
            if infrastructure:
                self.infrastructure_http_requests += 1

    def consume_dns_query(self) -> None:
        with self._lock:
            if self.dns_queries >= self.budget.max_dns_queries:
                raise ResourceBudgetExceeded("Investigation DNS-query budget exceeded")
            self.dns_queries += 1

    def consume_response_bytes(self, amount: int) -> None:
        if amount < 0:
            raise ValueError("Response byte accounting amount cannot be negative")
        with self._lock:
            self.response_bytes += amount
            if self.response_bytes > self.budget.max_response_bytes:
                raise ResourceBudgetExceeded("Investigation aggregate response-byte budget exceeded")

    def reserve_infrastructure_http_request(self) -> None:
        """Reserve an infrastructure request and mark it for the HTTP boundary.

        The marker prevents bounded_get() from counting the same HTTP request
        twice. It is task-local so concurrent execution attempts remain isolated.
        """
        self.reserve_http_request(infrastructure=True)
        current = _pending_infrastructure_reservations.get()
        _pending_infrastructure_reservations.set(current + 1)

    def consume_reserved_infrastructure_request(self) -> bool:
        current = _pending_infrastructure_reservations.get()
        if current <= 0:
            return False
        _pending_infrastructure_reservations.set(current - 1)
        return True

    def record_public_web_query(self, result_count: int) -> None:
        if result_count < 0:
            raise ValueError("Public Web result count cannot be negative")
        with self._lock:
            self.public_web_queries += 1
            self.public_web_results += result_count


def current_accounting() -> ExecutionResourceAccounting | None:
    return _current_accounting.get()


@contextmanager
def bind_accounting(accounting: ExecutionResourceAccounting) -> Iterator[None]:
    accounting_token = _current_accounting.set(accounting)
    pending_token = _pending_infrastructure_reservations.set(0)
    try:
        yield
    finally:
        _pending_infrastructure_reservations.reset(pending_token)
        _current_accounting.reset(accounting_token)


@dataclass(frozen=True)
class ExecutionResourceBudget:
    """Central guardrails for bounded passive investigation fan-out.

    Admission limits bound planned work, provider limits bound one provider
    result, per-response limits protect each network response, and
    ExecutionResourceAccounting enforces runtime outbound requests, DNS
    queries, aggregate response bytes, infrastructure requests, and Public
    Web query/result observations for one execution attempt.
    """

    max_provider_calls: int = 8
    max_candidate_probes: int = 4
    max_external_requests: int = 32
    max_response_bytes: int = 8 * 1024 * 1024
    max_dns_queries: int = 15
    max_infrastructure_http_requests: int = 2
    max_public_web_queries: int = 5
    max_public_web_results_per_query: int = 10
    max_persisted_findings: int = 100

    def validate(
        self,
        *,
        provider_calls: int,
        candidate_probes: int,
        estimated_external_requests: int,
        dns_queries: int = 0,
        infrastructure_http_requests: int = 0,
        response_bytes: int = 0,
        persisted_findings: int = 0,
    ) -> None:
        if provider_calls > self.max_provider_calls:
            raise RuntimeError("Investigation provider-call budget exceeded")
        if candidate_probes > self.max_candidate_probes:
            raise RuntimeError("Investigation candidate-probe budget exceeded")
        if estimated_external_requests > self.max_external_requests:
            raise RuntimeError("Investigation external-request budget exceeded")
        if response_bytes > self.max_response_bytes:
            raise RuntimeError("Investigation response-byte budget exceeded")
        if dns_queries > self.max_dns_queries:
            raise RuntimeError("Investigation DNS-query budget exceeded")
        if infrastructure_http_requests > self.max_infrastructure_http_requests:
            raise RuntimeError("Investigation infrastructure HTTP budget exceeded")
        if persisted_findings > self.max_persisted_findings:
            raise RuntimeError("Investigation persisted-finding budget exceeded")

    def accounting(self) -> ExecutionResourceAccounting:
        return ExecutionResourceAccounting(self)

    def public_web_bounds(self) -> tuple[int, int]:
        return self.max_public_web_queries, self.max_public_web_results_per_query

    def note_actual_response_accounting_limit(self) -> str:
        return "aggregate per-attempt response-byte limit enforced at outbound HTTP boundary"
