"""FastAPI application for SCADA Cyber-Physical Anomaly & Attack Detection."""

from contextlib import asynccontextmanager
from typing import Optional, List
import pandas as pd
from fastapi import FastAPI, HTTPException, status

from src.config import DEFAULT_SCADA_CONFIG
from src.generator import simulate_scada_stream
from src.model import train_scada_detector, ScadaCyberAnomalyDetectorBundle
from api.schemas import (
    ScadaTelemetryItem,
    ScadaEvaluationPoint,
    ScadaBatchEvaluationRequest,
    ScadaSimulationRequest,
    ScadaSimulationResponse,
    HealthResponse,
)

bundle: Optional[ScadaCyberAnomalyDetectorBundle] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global bundle
    artifact_path = DEFAULT_SCADA_CONFIG.artifacts_dir / DEFAULT_SCADA_CONFIG.model_filename
    if artifact_path.exists():
        try:
            bundle = ScadaCyberAnomalyDetectorBundle.load(str(artifact_path))
        except Exception:
            baseline = simulate_scada_stream(duration_steps=1800, attack_type="NONE", seed=42)
            bundle = train_scada_detector(baseline, config=DEFAULT_SCADA_CONFIG)
    else:
        baseline = simulate_scada_stream(duration_steps=1800, attack_type="NONE", seed=42)
        bundle = train_scada_detector(baseline, config=DEFAULT_SCADA_CONFIG)
    yield


app = FastAPI(
    title="SCADA Cyber-Physical Anomaly & Attack Detection API",
    description=(
        "Production industrial control system (ICS) telemetry analyzer. Combines "
        "unsupervised Isolation Forest with physical mass-balance invariants to intercept "
        "stealth False Data Injection (FDI), Replay Attacks, Valve Tampering, and Modbus DoS floods."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health", response_model=HealthResponse, tags=["Diagnostics"])
def health():
    return HealthResponse(
        status="healthy",
        detector_loaded=(bundle is not None),
        contamination_rate=DEFAULT_SCADA_CONFIG.contamination_rate,
        mass_res_threshold=bundle.mass_res_threshold if bundle else 0.003,
    )


@app.post("/evaluate/batch", response_model=List[ScadaEvaluationPoint], tags=["Inference"])
def evaluate_batch(req: ScadaBatchEvaluationRequest):
    """Evaluates arbitrary incoming SCADA telemetry frames."""
    if bundle is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Model bundle not initialized")

    df = pd.DataFrame([item.model_dump() for item in req.telemetry])
    preds = bundle.predict_stream(df)

    points: List[ScadaEvaluationPoint] = []
    for i, p in enumerate(preds):
        points.append(
            ScadaEvaluationPoint(
                timestamp_sec=float(df.iloc[i]["timestamp_sec"]),
                is_anomaly=p.is_anomaly,
                anomaly_score=p.anomaly_score,
                alert_level=p.alert_level,
                detected_attack_vector=p.detected_attack_vector,
                mitre_ics_tactic=p.mitre_ics_tactic,
                mass_balance_residual=p.mass_balance_residual,
                modbus_packet_rate_hz=p.modbus_packet_rate_hz,
            )
        )
    return points


@app.post("/simulate/attack", response_model=ScadaSimulationResponse, tags=["Simulation"])
def simulate_attack(req: ScadaSimulationRequest):
    """Simulates physical plant state under specified cyber-attack vector and benchmarks detection rate."""
    if bundle is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Model bundle not initialized")

    df = simulate_scada_stream(
        duration_steps=req.duration_steps,
        attack_type=req.attack_type,
        attack_start_step=req.attack_start_step,
        attack_duration_steps=req.attack_duration_steps,
        seed=req.seed,
    )
    preds = bundle.predict_stream(df)

    start = req.attack_start_step
    end = min(start + req.attack_duration_steps, len(preds))
    attack_window = preds[start:end]

    detected = [p for p in attack_window if p.is_anomaly]
    det_rate = (len(detected) / len(attack_window) * 100.0) if attack_window else 0.0

    # Dominant attack vector in detected window
    vectors = [p.detected_attack_vector for p in detected if p.detected_attack_vector != "NONE"]
    dominant_vector = max(set(vectors), key=vectors.count) if vectors else "NONE"
    tactics = [p.mitre_ics_tactic for p in detected if "Nominal" not in p.mitre_ics_tactic]
    dominant_tactic = max(set(tactics), key=tactics.count) if tactics else "N/A - Nominal Operation"

    sample_pts: List[ScadaEvaluationPoint] = []
    # Sample every 15th step for compact JSON response
    for step in range(0, len(preds), 15):
        p = preds[step]
        sample_pts.append(
            ScadaEvaluationPoint(
                timestamp_sec=float(df.iloc[step]["timestamp_sec"]),
                is_anomaly=p.is_anomaly,
                anomaly_score=p.anomaly_score,
                alert_level=p.alert_level,
                detected_attack_vector=p.detected_attack_vector,
                mitre_ics_tactic=p.mitre_ics_tactic,
                mass_balance_residual=p.mass_balance_residual,
                modbus_packet_rate_hz=p.modbus_packet_rate_hz,
            )
        )

    return ScadaSimulationResponse(
        attack_type=req.attack_type,
        duration_steps=req.duration_steps,
        attack_window_frames=len(attack_window),
        anomalies_detected_in_attack_window=len(detected),
        attack_window_detection_rate_pct=round(det_rate, 1),
        dominant_attack_vector=dominant_vector,
        dominant_mitre_tactic=dominant_tactic,
        sample_points=sample_pts,
    )
