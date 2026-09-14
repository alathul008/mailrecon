from dataclasses import dataclass


@dataclass(frozen=True)
class ExecutionResourceBudget:
    """Central guardrails for bounded passive investigation fan-out."""

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

    def public_web_bounds(self) -> tuple[int, int]:
        return self.max_public_web_queries, self.max_public_web_results_per_query

    def note_actual_response_accounting_limit(self) -> str:
        """Document the current boundary: HTTP bytes are hard-limited at the network layer.

        ProviderResult intentionally remains backward-compatible, so byte usage is not
        persisted or emitted as per-request telemetry. The hard limit is authoritative;
        exact aggregate byte accounting remains an observability enhancement rather than
        a safety prerequisite.
        """
        return "hard network response-byte limit; aggregate usage not persisted"
