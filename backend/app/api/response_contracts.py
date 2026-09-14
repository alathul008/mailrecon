from collections.abc import Iterable

from fastapi.routing import APIRoute
from fastapi.utils import create_model_field

from app.schemas.schemas import (
    AccountDiscoveryOut,
    CorrelationOut,
    CreateInvestigationOut,
    DeleteInvestigationOut,
    DemoOut,
    FindingOut,
    GraphOut,
    HealthOut,
    InvestigationOut,
    InvestigationSummaryOut,
    ProviderOut,
    RiskOut,
    ServiceCatalogOut,
    TimelineEventOut,
)


# The existing endpoint implementations intentionally keep their response
# construction unchanged. This registry makes the public JSON surfaces explicit
# to FastAPI/OpenAPI without redesigning or renaming any endpoint.
_RESPONSE_CONTRACTS = {
    ("GET", "/api/health"): HealthOut,
    ("GET", "/api/providers"): list[ProviderOut],
    ("POST", "/api/investigations"): CreateInvestigationOut,
    ("POST", "/api/demo"): DemoOut,
    ("GET", "/api/investigations"): list[InvestigationSummaryOut],
    ("GET", "/api/investigations/{inv_id}"): InvestigationOut,
    ("DELETE", "/api/investigations/{inv_id}"): DeleteInvestigationOut,
    ("GET", "/api/investigations/{inv_id}/findings"): list[FindingOut],
    ("GET", "/api/investigations/{inv_id}/risk"): RiskOut,
    ("GET", "/api/investigations/{inv_id}/timeline"): list[TimelineEventOut],
    ("GET", "/api/investigations/{inv_id}/graph"): GraphOut,
    ("GET", "/api/service-catalog"): list[ServiceCatalogOut],
    ("GET", "/api/investigations/{inv_id}/correlations"): CorrelationOut,
    ("GET", "/api/investigations/{inv_id}/account-discovery"): AccountDiscoveryOut,
}


def install_response_contracts(routes: Iterable[object]) -> None:
    """Attach explicit Pydantic response contracts to existing API routes.

    The route implementations predate centralized response models, so this
    keeps their return dictionaries and endpoint behavior intact while making
    the same shapes authoritative for runtime validation and generated OpenAPI.
    Binary/text report formats are deliberately excluded because their media
    types vary by the requested report format.
    """
    for route in routes:
        if not isinstance(route, APIRoute):
            continue
        methods = route.methods or set()
        model = next(
            (
                _RESPONSE_CONTRACTS.get((method, route.path))
                for method in methods
                if (method, route.path) in _RESPONSE_CONTRACTS
            ),
            None,
        )
        if model is None:
            continue
        route.response_model = model
        route.response_field = create_model_field(
            name=f"Response_{route.name}",
            type_=model,
            mode="serialization",
        )
        route.secure_cloned_response_field = route.response_field
