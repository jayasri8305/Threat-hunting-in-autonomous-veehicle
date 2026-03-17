"""
Shared Data Types for Dynamic Threat Hunting System.

All data classes and enumerations used across the project.
Based on SAE J2735 BSM (Basic Safety Message) standard for V2X communication.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


# ──────────────────────────────────────────────────
# Enumerations
# ──────────────────────────────────────────────────

class VehicleRole(Enum):
    """Role assigned to a vehicle in the simulation."""
    NORMAL = auto()
    POISONER = auto()
    GHOST_INJECTOR = auto()
    SPONGE_ATTACKER = auto()


class ThreatType(Enum):
    """Types of threats detected by the system."""
    NORMAL = 0
    POISONING = 1
    GHOST = 2
    SPONGE = 3
    UNKNOWN = 4          # OOD — flagged by energy score
    DOS = 5              # Common threat — volume based
    REPLAY = 6           # Common threat — temporal
    SYBIL = 7            # Common threat — identity


class PreventionAction(Enum):
    """Actions the Agentic Hunter can take."""
    NONE = auto()
    RATE_LIMIT = auto()          # Sponge / DoS
    ISOLATE = auto()             # Ghost / Sybil
    BLOCK = auto()               # Severe — full block
    ALERT = auto()               # Notify dashboard
    INVESTIGATE = auto()         # Enhanced monitoring
    MODEL_ROLLBACK = auto()      # Poisoning — restore checkpoint
    DATA_QUARANTINE = auto()     # Poisoning — remove bad data
    LOWER_THRESHOLD = auto()     # Heightened alertness


class AgentState(Enum):
    """Current state of the Agentic Hunter's OODA loop."""
    OBSERVE = auto()
    ORIENT = auto()
    DECIDE = auto()
    ACT = auto()


# ──────────────────────────────────────────────────
# Core Data Classes
# ──────────────────────────────────────────────────

@dataclass
class BSM:
    """
    Basic Safety Message — SAE J2735 standard.

    Part I (mandatory): position, speed, heading, acceleration.
    Extended with simulation metadata for threat detection.
    """
    sender_id: str
    position_x: float              # Latitude equiv (meters in sim)
    position_y: float              # Longitude equiv (meters in sim)
    speed: float                   # m/s
    heading: float                 # degrees (0=North, 90=East)
    acceleration: float            # m/s²
    timestamp: float = field(default_factory=time.time)
    sequence_number: int = 0       # Monotonically increasing per vehicle

    # Attack flags (ground truth — for labeling, not sent over network)
    is_poisoned: bool = False
    is_ghost: bool = False
    is_sponge: bool = False

    # Network metadata (added by V2X layer)
    rssi: float = 0.0             # Received signal strength
    latency_ms: float = 0.0       # Transmission latency

    def to_dict(self) -> dict:
        """Convert to JSON dict for UDP/CSV (matches old CARLA format)."""
        return {
            "vehicle_id": self.sender_id,
            "x": round(self.position_x, 4),
            "y": round(self.position_y, 4),
            "speed": round(self.speed, 4),
            "heading": round(self.heading, 2),
            "acceleration": round(self.acceleration, 4),
            "seq": self.sequence_number,
            "ts_pub": round(self.timestamp, 3),
            "latency_ms": round(self.latency_ms, 2),
            "rssi": round(self.rssi, 3),
            "spoofed": self.is_poisoned or self.is_ghost or self.is_sponge,
        }


@dataclass
class VehicleState:
    """Complete state of a vehicle at a point in time."""
    vehicle_id: str
    role: VehicleRole = VehicleRole.NORMAL
    position_x: float = 0.0
    position_y: float = 0.0
    speed: float = 0.0
    heading: float = 0.0
    acceleration: float = 0.0
    trust_score: float = 0.5
    is_active: bool = True
    bsm_count: int = 0
    steps_alive: int = 0
    current_road_id: str = ""


@dataclass
class RSUMetrics:
    """
    Resource metrics for the Road-Side Unit (edge server).
    
    These are critical for sponge attack detection — the agent monitors
    CPU and memory to detect resource exhaustion attacks.
    """
    cpu_usage_pct: float = 0.0
    memory_usage_mb: float = 0.0
    avg_response_time_ms: float = 0.0
    active_connections: int = 0
    bsms_processed: int = 0
    bsms_dropped: int = 0
    queue_depth: int = 0
    is_overloaded: bool = False


@dataclass
class DetectionResult:
    """Output from the 3-stage detection pipeline for one vehicle."""
    vehicle_id: str
    step: int

    # Stage 1: GCL anomaly score
    gcl_anomaly_score: float = 0.0

    # Stage 2: Classifier output
    predicted_class: ThreatType = ThreatType.NORMAL
    class_probabilities: dict = field(default_factory=dict)
    confidence: float = 0.0

    # Stage 2: OOD energy score
    energy_score: float = 0.0
    is_ood: bool = False

    # Stage 3: Agentic Hunter decision
    agent_decision: PreventionAction = PreventionAction.NONE
    agent_confidence: float = 0.0
    investigation_notes: str = ""

    # Final combined result
    final_label: ThreatType = ThreatType.NORMAL
    is_threat: bool = False


@dataclass
class ThreatEvent:
    """A logged threat event for the dashboard."""
    step: int
    vehicle_id: str
    threat_type: ThreatType
    confidence: float
    action_taken: PreventionAction
    details: str = ""


@dataclass
class SimulationSnapshot:
    """Complete state of one simulation step."""
    step: int
    vehicles: list = field(default_factory=list)    # List of VehicleState
    bsms: list = field(default_factory=list)         # List of BSM
    rsu_metrics: RSUMetrics = field(default_factory=RSUMetrics)
    threats_active: list = field(default_factory=list)  # List of ThreatEvent
    detections: list = field(default_factory=list)       # List of DetectionResult
