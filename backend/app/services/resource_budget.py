from dataclasses import dataclass, field
from threading import Lock


@dataclass
class ExecutionResourceAccounting:
    """Runtime accounting shared by one execution attempt.

    Admission limits describe planned work; this object accounts actual runtime
    consumption. It is intentionally in-memory because the current deployment
    is a single-user/local service and no persistent counter is required.
    """

    budget: "ExecutionResourceBudget"
    response_bytes: int = 0
    infrastructure_http_requests: int = 0
    _lock: Lock = field(default_factory=Lock, repr=False, compare=False)

    def consume_response_bytes(self, amount: int) -> None:
        if amount < 0:
            raise ValueError("Response byte accounting amount cannot be negative")
        with self._lock:
            self.response_bytes += amount
            if self.response_bytes > self.budget.max_response_bytes:
                raise RuntimeError("Investigation aggregate response-byte budget exceeded")

    def reserve_infrastructure_http_request(self) -> None:
        with self._lock:
            if self.infrastructure_http_requests >= self.budget.max_infrastructure_http_requests:
                raise RuntimeError("Investigation infrastructure HTTP budget exceeded")
            self.infrastructure_http_requests += 1


@dataclass(frozen=True)
class ExecutionResourceBudget:
    """Central guardrails for bounded passive investigation fan-out.

    Dimensions are intentionally distinct: admission limits bound planned work,
    provider limits bound one provider result, per-response limits protect each
    network response, and ExecutionResourceAccounting enforces aggregate runtime
    response bytes and infrastructure requests for one execution attempt.
    """

    max_provider_calls: int = 8
    max_candidate_probes: int = 4
    max_external_requests: int = 32
    # Aggregate bytes per execution attempt. bounded_get also enforces this
    # value as the per-response hard ceiling.
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
        """Describe the runtime aggregate response-byte invariant."""
        return "aggregate per-attempt response-byte limit enforced at outbound HTTP boundary"
