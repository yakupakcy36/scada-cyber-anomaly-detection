"""Cyber-physical feature extraction and physical conservation invariant checks."""

from typing import Tuple, List
import numpy as np
import pandas as pd
from src.config import ScadaConfig, DEFAULT_SCADA_CONFIG


class ScadaFeatureExtractor:
    """Extracts multivariate physical invariant residuals and temporal telemetry dynamics."""

    def __init__(self, config: ScadaConfig = DEFAULT_SCADA_CONFIG):
        self.config = config

    def extract_features(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Transforms raw SCADA telemetry into physics-augmented feature space.
        Returns feature matrix X and attack label series y (if present).
        """
        data = df.copy()

        # 1. First-Order Temporal Derivatives
        data["dh_dt"] = data["water_level_m"].diff().fillna(0.0)
        data["dp_dt"] = data["pressure_bar"].diff().fillna(0.0)
        data["dflow_in_dt"] = data["pump_inflow_lps"].diff().fillna(0.0)

        # 2. Physics-Based Conservation of Mass Invariant Residual
        # Delta Level theoretical = (Q_in - Q_out) / (1000 * Area)
        dt = self.config.sampling_rate_sec
        expected_dh = ((data["pump_inflow_lps"] - data["valve_outflow_lps"]) / (1000.0 * self.config.tank_area_sq_meters)) * dt
        data["mass_balance_residual"] = np.abs(data["dh_dt"] - expected_dh)

        # 3. Hydrostatic + Dynamic Pressure Invariant Residual
        # Expected pressure bar = level * 0.0981 + 3.7 + (pump_inflow * 0.005)
        expected_p = (data["water_level_m"] * 0.0981) + 3.7 + (data["pump_inflow_lps"] * 0.005)
        data["hydrostatic_residual"] = np.abs(data["pressure_bar"] - expected_p)

        # 4. Rolling Statistical Descriptors (10s and 30s)
        for w in [10, 30]:
            data[f"level_std_{w}s"] = data["water_level_m"].rolling(w, min_periods=1).std().fillna(0.0)
            data[f"pressure_std_{w}s"] = data["pressure_bar"].rolling(w, min_periods=1).std().fillna(0.0)
            data[f"packet_rate_mean_{w}s"] = data["modbus_packet_rate_hz"].rolling(w, min_periods=1).mean().fillna(10.0)
            data[f"crc_errors_sum_{w}s"] = data["modbus_crc_errors"].rolling(w, min_periods=1).sum().fillna(0.0)

        # Feature column selection
        feature_cols = [
            "water_level_m",
            "pump_inflow_lps",
            "valve_outflow_lps",
            "pressure_bar",
            "dh_dt",
            "dp_dt",
            "dflow_in_dt",
            "mass_balance_residual",
            "hydrostatic_residual",
            "level_std_10s",
            "pressure_std_10s",
            "packet_rate_mean_10s",
            "crc_errors_sum_10s",
            "level_std_30s",
            "pressure_std_30s",
            "packet_rate_mean_30s",
            "crc_errors_sum_30s",
        ]

        X = data[feature_cols].copy()
        y = data["is_attack"] if "is_attack" in data.columns else pd.Series(False, index=data.index)

        return X, y
