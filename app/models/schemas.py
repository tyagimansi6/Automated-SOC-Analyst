"""SQLModel table entities and Pydantic v2 API schemas for the SOC backend.

Graph node/edge read models follow React Flow field names (`id`, `position`,
`data`, `source`, `target`) and can be mapped to D3 (`nodes` / `links`).
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import JSON, Column
from sqlmodel import Field as SQLField, Relationship, SQLModel

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class EventType(str, Enum):
    LOGIN = "login"
    LOGOUT = "logout"
    AUTH_FAILURE = "auth_failure"
    FILE_ACCESS = "file_access"
    PROCESS_START = "process_start"
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    MALWARE_DETECTED = "malware_detected"


class EventStatus(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    SUSPICIOUS = "suspicious"


class AlertStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class GraphNodeType(str, Enum):
    USER = "user"
    COMPUTER = "computer"
    SERVER = "server"
    HOST = "host"
    IP = "ip"
    PROCESS = "process"
    FILE = "file"
    DOMAIN = "domain"
    SERVICE = "service"
    ALERT = "alert"


class GraphEdgeType(str, Enum):
    AUTHENTICATED_TO = "authenticated_to"
    CONNECTED_TO = "connected_to"
    COMMUNICATED_WITH = "communicated_with"
    AUTHENTICATED_AS = "authenticated_as"
    ACCESSED = "accessed"
    SPAWNED = "spawned"
    BELONGS_TO = "belongs_to"
    LATERAL_TO = "lateral_to"
    TRIGGERED = "triggered"


class RemediationActionType(str, Enum):
    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    BLOCK_IP = "block_ip"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    RESET_CREDENTIALS = "reset_credentials"
    NOTIFY_ANALYST = "notify_analyst"


class RemediationStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# SQLModel entities
# ---------------------------------------------------------------------------


class TelemetryEvent(SQLModel, table=True):
    """Ingested telemetry row used by the simulation replay engine."""

    __tablename__ = "telemetry_events"

    id: UUID = SQLField(default_factory=uuid4, primary_key=True)
    timestamp: datetime = SQLField(index=True)
    source: str = SQLField(index=True, max_length=255)
    destination: str = SQLField(max_length=255)
    user: str = SQLField(index=True, max_length=255)
    event_type: EventType = SQLField(index=True)
    status: EventStatus = SQLField(index=True)


class Alert(SQLModel, table=True):
    """Scored SOC alert produced from telemetry / graph analysis."""

    __tablename__ = "alerts"

    id: UUID = SQLField(default_factory=uuid4, primary_key=True)
    risk_score: float = SQLField(ge=0.0, le=100.0, index=True)
    entity: str = SQLField(index=True, max_length=255)
    status: AlertStatus = SQLField(default=AlertStatus.OPEN, index=True)
    created_at: datetime = SQLField(default_factory=utc_now, index=True)

    remediations: list["RemediationAction"] = Relationship(back_populates="alert")


class GraphNode(SQLModel, table=True):
    """Persisted graph vertex; layout fields feed React Flow / D3 export."""

    __tablename__ = "graph_nodes"

    id: UUID = SQLField(default_factory=uuid4, primary_key=True)
    label: str = SQLField(max_length=255)
    node_type: GraphNodeType = SQLField(index=True)
    entity: str = SQLField(index=True, max_length=255)
    risk_score: float = SQLField(default=0.0, ge=0.0, le=100.0)
    position_x: float = SQLField(default=0.0)
    position_y: float = SQLField(default=0.0)
    properties: dict[str, Any] = SQLField(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    created_at: datetime = SQLField(default_factory=utc_now)


class GraphEdge(SQLModel, table=True):
    """Persisted graph edge; `source_id` / `target_id` map to React Flow handles."""

    __tablename__ = "graph_edges"

    id: UUID = SQLField(default_factory=uuid4, primary_key=True)
    source_id: UUID = SQLField(foreign_key="graph_nodes.id", index=True)
    target_id: UUID = SQLField(foreign_key="graph_nodes.id", index=True)
    edge_type: GraphEdgeType = SQLField(index=True)
    label: str | None = SQLField(default=None, max_length=255)
    weight: float = SQLField(default=1.0, ge=0.0)
    animated: bool = SQLField(default=False)
    properties: dict[str, Any] = SQLField(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    created_at: datetime = SQLField(default_factory=utc_now)


class RemediationAction(SQLModel, table=True):
    """Containment / response action tied to an alert."""

    __tablename__ = "remediation_actions"

    id: UUID = SQLField(default_factory=uuid4, primary_key=True)
    alert_id: UUID = SQLField(foreign_key="alerts.id", index=True)
    action_type: RemediationActionType = SQLField(index=True)
    target_entity: str = SQLField(max_length=255)
    status: RemediationStatus = SQLField(
        default=RemediationStatus.PENDING,
        index=True,
    )
    parameters: dict[str, Any] = SQLField(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    result: str | None = SQLField(default=None)
    created_at: datetime = SQLField(default_factory=utc_now)
    completed_at: datetime | None = SQLField(default=None)

    alert: Alert | None = Relationship(back_populates="remediations")


# ---------------------------------------------------------------------------
# Pydantic v2 API schemas — TelemetryEvent
# ---------------------------------------------------------------------------


class TelemetryEventCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    source: str = Field(min_length=1, max_length=255)
    destination: str = Field(min_length=1, max_length=255)
    user: str = Field(min_length=1, max_length=255)
    event_type: EventType
    status: EventStatus


class TelemetryEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    timestamp: datetime
    source: str
    destination: str
    user: str
    event_type: EventType
    status: EventStatus


# ---------------------------------------------------------------------------
# Pydantic v2 API schemas — Alert
# ---------------------------------------------------------------------------


class AlertCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_score: float = Field(ge=0.0, le=100.0)
    entity: str = Field(min_length=1, max_length=255)
    status: AlertStatus = AlertStatus.OPEN


class AlertUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_score: float | None = Field(default=None, ge=0.0, le=100.0)
    entity: str | None = Field(default=None, min_length=1, max_length=255)
    status: AlertStatus | None = None


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    risk_score: float
    entity: str
    status: AlertStatus
    created_at: datetime


# ---------------------------------------------------------------------------
# Pydantic v2 API schemas — GraphNode / GraphEdge (React Flow + D3)
# ---------------------------------------------------------------------------


class Position(BaseModel):
    """React Flow / canvas coordinates."""

    x: float = 0.0
    y: float = 0.0


class GraphNodeData(BaseModel):
    """Node payload consumed by React Flow `data` and D3 node attributes."""

    label: str
    entity_type: GraphNodeType
    entity: str
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphNodeCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=255)
    node_type: GraphNodeType
    entity: str = Field(min_length=1, max_length=255)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    position: Position = Field(default_factory=Position)
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphNodeRead(BaseModel):
    """React Flow node: `{ id, type, position, data }`."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    type: str | None = None
    position: Position = Field(default_factory=Position)
    data: GraphNodeData

    @model_validator(mode="before")
    @classmethod
    def from_sqlmodel(cls, value: Any) -> Any:
        if isinstance(value, GraphNode):
            return {
                "id": str(value.id),
                "type": value.node_type.value,
                "position": {"x": value.position_x, "y": value.position_y},
                "data": {
                    "label": value.label,
                    "entity_type": value.node_type,
                    "entity": value.entity,
                    "risk_score": value.risk_score,
                    "properties": value.properties or {},
                },
            }
        return value


class GraphEdgeData(BaseModel):
    """Edge payload consumed by React Flow `data` and D3 link attributes."""

    edge_type: GraphEdgeType
    weight: float = Field(default=1.0, ge=0.0)
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphEdgeCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: UUID
    target_id: UUID
    edge_type: GraphEdgeType
    label: str | None = Field(default=None, max_length=255)
    weight: float = Field(default=1.0, ge=0.0)
    animated: bool = False
    properties: dict[str, Any] = Field(default_factory=dict)

    @field_validator("target_id")
    @classmethod
    def reject_self_loop(cls, target_id: UUID, info: Any) -> UUID:
        source_id = info.data.get("source_id")
        if source_id is not None and target_id == source_id:
            raise ValueError("source_id and target_id must be different")
        return target_id


class GraphEdgeRead(BaseModel):
    """React Flow edge: `{ id, source, target, type, label, animated, data }`."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    source: str
    target: str
    type: str | None = None
    label: str | None = None
    animated: bool = False
    data: GraphEdgeData | None = None

    @model_validator(mode="before")
    @classmethod
    def from_sqlmodel(cls, value: Any) -> Any:
        if isinstance(value, GraphEdge):
            return {
                "id": str(value.id),
                "source": str(value.source_id),
                "target": str(value.target_id),
                "type": value.edge_type.value,
                "label": value.label,
                "animated": value.animated,
                "data": {
                    "edge_type": value.edge_type,
                    "weight": value.weight,
                    "properties": value.properties or {},
                },
            }
        return value


class GraphRead(BaseModel):
    """Full graph snapshot for React Flow (`nodes` / `edges`)."""

    nodes: list[GraphNodeRead]
    edges: list[GraphEdgeRead]


class D3Node(BaseModel):
    """D3 force-graph node."""

    id: str
    group: str
    label: str
    risk_score: float = 0.0


class D3Link(BaseModel):
    """D3 force-graph link (`links` array)."""

    source: str
    target: str
    value: float = 1.0


class D3Graph(BaseModel):
    """D3-compatible export of the same SOC graph."""

    nodes: list[D3Node]
    links: list[D3Link]


# ---------------------------------------------------------------------------
# Pydantic v2 API schemas — RemediationAction
# ---------------------------------------------------------------------------


class RemediationActionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: UUID
    action_type: RemediationActionType
    target_entity: str = Field(min_length=1, max_length=255)
    status: RemediationStatus = RemediationStatus.PENDING
    parameters: dict[str, Any] = Field(default_factory=dict)


class RemediationActionUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: RemediationStatus | None = None
    result: str | None = None
    completed_at: datetime | None = None
    parameters: dict[str, Any] | None = None


class RemediationActionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    alert_id: UUID
    action_type: RemediationActionType
    target_entity: str
    status: RemediationStatus
    parameters: dict[str, Any]
    result: str | None
    created_at: datetime
    completed_at: datetime | None


# ---------------------------------------------------------------------------
# Pydantic v2 API schemas — Health & simulation control
# ---------------------------------------------------------------------------


class HealthRead(BaseModel):
    status: Literal["ok"] = "ok"
    service: str
    version: str
    simulation_state: str
    websocket_connections: int = Field(ge=0)
    graph_nodes: int = Field(ge=0)
    graph_edges: int = Field(ge=0)


class SimulationStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_path: str = Field(min_length=1)
    speed_multiplier: float = Field(default=1.0, gt=0)
    limit: int = Field(default=1000, ge=1)


class SimulationStatusRead(BaseModel):
    state: str
    message: str = ""
