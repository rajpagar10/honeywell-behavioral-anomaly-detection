"""Shared domain enumerations."""

from enum import StrEnum


class EntityType(StrEnum):
    """Supported identity and device categories."""

    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    IOT_DEVICE = "iot_device"
    EDGE_DEVICE = "edge_device"


class AttackType(StrEnum):
    """Canonical normal and attack labels."""

    NORMAL = "normal"
    BRUTE_FORCE = "brute_force"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    CREDENTIAL_STUFFING = "credential_stuffing"
    LATERAL_MOVEMENT = "lateral_movement"
    DEVICE_SPOOFING = "device_spoofing"
    LOW_AND_SLOW_EXFILTRATION = "low_and_slow_exfiltration"
    INSIDER_DRIFT = "insider_drift"


class AuthenticationMethod(StrEnum):
    """Authentication mechanisms represented in access events."""

    PASSWORD = "password"
    MFA = "mfa"
    SSO = "sso"
    CERTIFICATE = "certificate"
    API_KEY = "api_key"
    SERVICE_TOKEN = "service_token"
    BIOMETRIC = "biometric"


class AuthenticationOutcome(StrEnum):
    """Result of an authentication attempt."""

    SUCCESS = "success"
    FAILURE = "failure"
    CHALLENGE = "challenge"


class ResourceSensitivity(StrEnum):
    """Business impact classification for resources."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Severity(StrEnum):
    """SOC alert severity bands."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(StrEnum):
    """Alert lifecycle states."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


class AnalystDisposition(StrEnum):
    """Analyst conclusions used for audit and controlled learning."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_CHANGE = "benign_change"
    NEEDS_MORE_INFORMATION = "needs_more_information"


class AnalystQuestion(StrEnum):
    """Grounded questions supported by the Investigation Copilot."""

    EXECUTIVE_SUMMARY = "executive_summary"
    WHY_GENERATED = "why_generated"
    ABNORMAL_BEHAVIORS = "abnormal_behaviors"
    HIGH_RISK_SCORE = "high_risk_score"
    CONCEPT_DRIFT = "concept_drift"
    INVESTIGATE_FIRST = "investigate_first"


class InvestigationFeedback(StrEnum):
    """Analyst feedback choices exposed by the investigation workspace."""

    CONFIRMED_THREAT = "confirmed_threat"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"
    NEEDS_INVESTIGATION = "needs_investigation"


class ModelFamily(StrEnum):
    """Detection model families used by the model registry."""

    RULE = "rule"
    STATISTICAL = "statistical"
    AUTOENCODER = "autoencoder"
    CLASSIFIER = "classifier"
    SEQUENCE = "sequence"


class EvidenceDirection(StrEnum):
    """Whether evidence increases or mitigates risk."""

    INCREASES_RISK = "increases_risk"
    MITIGATES_RISK = "mitigates_risk"


class RiskFactorName(StrEnum):
    """Required inputs to the versioned risk policy."""

    BEHAVIORAL_DEVIATION = "behavioral_deviation"
    ML_CONFIDENCE = "ml_confidence"
    ATTACK_SEVERITY = "attack_severity"
    HISTORICAL_TRUST = "historical_trust"
    RESOURCE_SENSITIVITY = "resource_sensitivity"
    DEVICE_TRUST = "device_trust"
    GEO_TRUST = "geo_trust"
    SEQUENCE_ANOMALY = "sequence_anomaly"
    RULE_CONFIDENCE = "rule_confidence"
