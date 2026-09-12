from dataclasses import dataclass


@dataclass(frozen=True)
class ExecutionResourceBudget:
    """Small central guardrail for deterministic investigation fan-out."""

    max_provider_calls: int = 8
    max_candidate_probes: int = 4
    max_external_requests: int = 32
    max_public_web_queries: int = 5
    max_public_web_results_per_query: int = 10

    def validate(self, *, provider_calls: int, candidate_probes: int, estimated_external_requests: int) -> None:
        if provider_calls > self.max_provider_calls:
            raise RuntimeError("Investigation provider-call budget exceeded")
        if candidate_probes > self.max_candidate_probes:
            raise RuntimeError("Investigation candidate-probe budget exceeded")
        if estimated_external_requests > self.max_external_requests:
            raise RuntimeError("Investigation external-request budget exceeded")

    def public_web_bounds(self) -> tuple[int, int]:
        return self.max_public_web_queries, self.max_public_web_results_per_query
