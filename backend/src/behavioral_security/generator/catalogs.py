"""Curated fictional enterprise locations, resources, and command templates."""

from typing import Final

from behavioral_security.core.models.common import GeoLocation

LOCATIONS: Final[tuple[GeoLocation, ...]] = (
    GeoLocation(country_code="IN", city="Bengaluru", latitude=12.9716, longitude=77.5946),
    GeoLocation(country_code="IN", city="Hyderabad", latitude=17.3850, longitude=78.4867),
    GeoLocation(country_code="IN", city="Pune", latitude=18.5204, longitude=73.8567),
    GeoLocation(country_code="IN", city="Chennai", latitude=13.0827, longitude=80.2707),
    GeoLocation(country_code="DE", city="Frankfurt", latitude=50.1109, longitude=8.6821),
    GeoLocation(country_code="SG", city="Singapore", latitude=1.3521, longitude=103.8198),
    GeoLocation(country_code="US", city="Phoenix", latitude=33.4484, longitude=-112.0740),
)

DEPARTMENTS: Final[tuple[str, ...]] = (
    "engineering",
    "operations",
    "finance",
    "security",
    "manufacturing",
    "human-resources",
)

DEPARTMENT_RESOURCES: Final[dict[str, tuple[str, ...]]] = {
    "engineering": (
        "engineering/git",
        "engineering/build-system",
        "engineering/telemetry",
        "shared/document-portal",
    ),
    "operations": (
        "operations/fleet-console",
        "operations/work-orders",
        "operations/site-dashboard",
        "shared/document-portal",
    ),
    "finance": (
        "finance/erp",
        "finance/reporting",
        "finance/vendor-portal",
        "shared/document-portal",
    ),
    "security": (
        "security/siem",
        "security/case-management",
        "security/identity-console",
        "shared/document-portal",
    ),
    "manufacturing": (
        "manufacturing/mes",
        "manufacturing/quality",
        "manufacturing/line-status",
        "shared/document-portal",
    ),
    "human-resources": (
        "hr/human-capital",
        "hr/recruiting",
        "hr/learning",
        "shared/document-portal",
    ),
}

SERVICE_RESOURCES: Final[tuple[str, ...]] = (
    "platform/service-registry",
    "platform/secrets-broker",
    "platform/metrics",
    "platform/message-bus",
)

IOT_RESOURCES: Final[tuple[str, ...]] = (
    "iot/telemetry-ingest",
    "iot/device-shadow",
    "iot/firmware-status",
)

EDGE_RESOURCES: Final[tuple[str, ...]] = (
    "edge/site-gateway",
    "edge/configuration",
    "edge/telemetry-relay",
    "edge/maintenance",
)

RARE_SENSITIVE_RESOURCES: Final[tuple[str, ...]] = (
    "identity/domain-controller",
    "platform/privileged-vault",
    "finance/payroll-export",
    "engineering/design-archive",
    "operations/site-controller",
)

COMMAND_TEMPLATES: Final[dict[str, tuple[str, ...]]] = {
    "user": ("authenticate", "open", "read", "logout"),
    "service_account": ("token_exchange", "read_config", "write_metric", "commit"),
    "iot_device": ("authenticate_certificate", "publish_telemetry", "heartbeat"),
    "edge_device": ("authenticate_certificate", "sync", "publish_batch", "heartbeat"),
}
