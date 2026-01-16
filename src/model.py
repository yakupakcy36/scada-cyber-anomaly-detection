"""Unsupervised Isolation Forest and Cyber-Physical Invariant Anomaly Detector."""

import os
from dataclasses import dataclass
from typing import Dict, Any, Tuple, List
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from src.config import ScadaConfig, DEFAULT_SCADA_CONFIG
from src.features import ScadaFeatureExtractor


@dataclass
class ScadaAnomalyPrediction:
    is_anomaly: bool
    anomaly_score: float  # [0.0 - 1.0]
    alert_level: str  # NOMINAL, SUSPICIOUS, ATTACK_CONFIRMED
    detected_attack_vector: str
    mitre_ics_tactic: str
    mass_balance_residual: float
    modbus_packet_rate_hz: float


class ScadaCyberAnomalyDetectorBundle:
    """Production SCADA cyber-physical anomaly detection engine."""

    def __init__(
        self,
        scaler: StandardScaler,
        isolation_forest: IsolationForest,
        feature_names: List[str],
        threshold: float = 0.55,
        mass_res_threshold: float = 0.003,
        config: ScadaConfig = DEFAULT_SCADA_CONFIG,
    ):
        self.scaler = scaler
        self.isolation_forest = isolation_forest
        self.feature_names = feature_names
        self.threshold = threshold
        self.mass_res_threshold = mass_res_threshold
        self.config = config

    def predict_stream(self, df: pd.DataFrame) -> List[ScadaAnomalyPrediction]:
        """Evaluates batch or streaming SCADA telemetry records."""
        extractor = ScadaFeatureExtractor(config=self.config)
        X, _ = extractor.extract_features(df)
        X_aligned = X[self.feature_names]
        X_scaled = self.scaler.transform(X_aligned)

        # Isolation forest scores: lower values mean more anomalous
        raw_scores = self.isolation_forest.decision_function(X_scaled)
        # Normalize to 0 (nominal) -> 1 (anomalous)
        norm_scores = np.clip(0.5 - (raw_scores * 2.0), 0.0, 1.0)

        results: List[ScadaAnomalyPrediction] = []
        for i in range(len(df)):
            score = float(norm_scores[i])
            mass_res = float(X.iloc[i]["mass_balance_residual"])
            hydro_res = float(X.iloc[i]["hydrostatic_residual"])
            packet_rate = float(df.iloc[i]["modbus_packet_rate_hz"])
            crc_errs = int(df.iloc[i]["modbus_crc_errors"])
            level = float(df.iloc[i]["water_level_m"])
            outflow = float(df.iloc[i]["valve_outflow_lps"])

            # Physical Invariant Trigger override
            is_anomaly = (
                (score >= self.threshold)
                or (mass_res > self.mass_res_threshold)
                or (hydro_res > 0.20)
                or (packet_rate > 70.0)
                or (outflow > 95.0)
                or (level < 1.0)
                or (level > 9.0)
            )

            # Attack Vector Diagnostic Classification & MITRE ICS Mapping
            if not is_anomaly:
                attack_vec = "NONE"
                mitre_tag = "N/A - Nominal Operation"
                alert_lvl = "NOMINAL"
            elif packet_rate > 70.0 or crc_errs > 3:
                attack_vec = "MODBUS_DOS_FLOOD"
                mitre_tag = "MITRE ICS T0814: Denial of Service"
                alert_lvl = "ATTACK_CONFIRMED"
                score = max(score, 0.95)
            elif mass_res > self.mass_res_threshold:
                attack_vec = "STEALTH_FALSE_DATA_INJECTION"
                mitre_tag = "MITRE ICS T0815: Point & Tag Manipulation"
                alert_lvl = "ATTACK_CONFIRMED"
                score = max(score, 0.92)
            elif hydro_res > 0.15:
                attack_vec = "REPLAY_ATTACK"
                mitre_tag = "MITRE ICS T0839: Replay / Sensor Manipulation"
                alert_lvl = "ATTACK_CONFIRMED"
                score = max(score, 0.95)
            elif outflow > 95.0 or level < 1.0 or level > 9.0:
                attack_vec = "VALVE_TAMPERING"
                mitre_tag = "MITRE ICS T0855: Unauthorized Command Message"
                alert_lvl = "ATTACK_CONFIRMED"
                score = max(score, 0.90)
            else:
                attack_vec = "UNSPECIFIED_ANOMALY"
                mitre_tag = "MITRE ICS T0807: Command, Control & Deviation"
                alert_lvl = "SUSPICIOUS" if score < 0.75 else "ATTACK_CONFIRMED"

            results.append(
                ScadaAnomalyPrediction(
                    is_anomaly=is_anomaly,
                    anomaly_score=round(float(score), 3),
                    alert_level=alert_lvl,
                    detected_attack_vector=attack_vec,
                    mitre_ics_tactic=mitre_tag,
                    mass_balance_residual=round(mass_res, 4),
                    modbus_packet_rate_hz=round(packet_rate, 1),
                )
            )

        return results

    def save(self, filepath: str) -> None:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self, filepath)

    @classmethod
    def load(cls, filepath: str) -> "ScadaCyberAnomalyDetectorBundle":
        return joblib.load(filepath)


def train_scada_detector(
    nominal_df: pd.DataFrame,
    config: ScadaConfig = DEFAULT_SCADA_CONFIG,
) -> ScadaCyberAnomalyDetectorBundle:
    """Trains unsupervised Isolation Forest on strictly attack-free nominal data."""
    extractor = ScadaFeatureExtractor(config=config)
    X, _ = extractor.extract_features(nominal_df)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    iso = IsolationForest(
        n_estimators=120,
        contamination=config.contamination_rate,
        random_state=config.random_seed,
        n_jobs=-1,
    )
    iso.fit(X_scaled)

    calibrated_mass_res = float(np.percentile(X["mass_balance_residual"], 99.5)) * 2.5

    bundle = ScadaCyberAnomalyDetectorBundle(
        scaler=scaler,
        isolation_forest=iso,
        feature_names=list(X.columns),
        threshold=0.55,
        mass_res_threshold=max(0.002, calibrated_mass_res),
        config=config,
    )
    return bundle
