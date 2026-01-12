"""Configuration constants for SCADA Cyber-Physical Anomaly Detection."""

from dataclasses import dataclass
from pathlib import Path
from typing import Tuple


@dataclass(frozen=True)
class ScadaConfig:
    sampling_rate_sec: float = 1.0
    history_window_steps: int = 30  # 30-second rolling sliding window

    # Physical Reservoir & Valve parameters
    tank_area_sq_meters: float = 5.0
    nominal_water_level_m: float = 5.0
    min_water_level_m: float = 0.5
    max_water_level_m: float = 9.5
    max_inflow_rate_lps: float = 120.0
    max_outflow_rate_lps: float = 120.0
    nominal_pressure_bar: float = 4.2

    # Anomaly detector hyperparams
    contamination_rate: float = 0.03
    random_seed: int = 42

    # Storage paths
    artifacts_dir: Path = Path("artifacts")
    model_filename: str = "scada_cyber_detector_bundle.joblib"


DEFAULT_SCADA_CONFIG = ScadaConfig()
