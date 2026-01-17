"""Pydantic schemas for the SCADA Cyber-Physical Anomaly API."""

from typing import List, Optional
from pydantic import BaseModel, Field


class ScadaTelemetryItem(BaseModel):
    timestamp_sec: float
    water_level_m: float
    pump_inflow_lps: float
    valve_outflow_lps: float
    pressure_bar: float
    water_temp_c: float = 20.0
    modbus_packet_rate_hz: float = 10.0
    modbus_crc_errors: int = 0


class ScadaEvaluationPoint(BaseModel):
    timestamp_sec: float
    is_anomaly: bool
    anomaly_score: float
    alert_level: str
    detected_attack_vector: str
    mitre_ics_tactic: str
    mass_balance_residual: float
    modbus_packet_rate_hz: float


class ScadaBatchEvaluationRequest(BaseModel):
    telemetry: List[ScadaTelemetryItem]


class ScadaSimulationRequest(BaseModel):
    attack_type: str = Field(
        default="FDI",
        description="NONE, FDI, REPLAY, VALVE_TAMPER, DOS_FLOOD",
    )
    duration_steps: int = Field(default=300, ge=50, le=1200)
    attack_start_step: int = Field(default=100, ge=10)
    attack_duration_steps: int = Field(default=120, ge=10)
    seed: int = Field(default=42, ge=0)


class ScadaSimulationResponse(BaseModel):
    attack_type: str
    duration_steps: int
    attack_window_frames: int
    anomalies_detected_in_attack_window: int
    attack_window_detection_rate_pct: float
    dominant_attack_vector: str
    dominant_mitre_tactic: str
    sample_points: List[ScadaEvaluationPoint]


class HealthResponse(BaseModel):
    status: str
    detector_loaded: bool
    contamination_rate: float
    mass_res_threshold: float
