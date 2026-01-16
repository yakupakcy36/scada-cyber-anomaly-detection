"""CLI runner for training and evaluating SCADA cyber-physical anomaly detection."""

import argparse
from pathlib import Path
from src.config import DEFAULT_SCADA_CONFIG
from src.generator import simulate_scada_stream
from src.model import train_scada_detector, ScadaCyberAnomalyDetectorBundle


def run_pipeline(save_artifact: bool = True):
    print("=" * 68)
    print("SCADA CYBER-PHYSICAL INTRUSION & ANOMALY DETECTOR: BENCHMARK")
    print("=" * 68)

    print("[1/3] Generating nominal operational SCADA baseline telemetry...")
    nominal_df = simulate_scada_stream(duration_steps=1800, attack_type="NONE", seed=42)
    print(f"      Simulated {len(nominal_df)} nominal 1-second telemetry frames")

    print("\n[2/3] Training Unsupervised Isolation Forest & Invariant Rules...")
    bundle = train_scada_detector(nominal_df, config=DEFAULT_SCADA_CONFIG)
    print("      Trained 120-tree Isolation Forest with Standard Scaler")

    print("\n[3/3] Evaluating on Real-World Cyber Attack Scenarios:")
    attack_scenarios = ["NONE", "FDI", "REPLAY", "VALVE_TAMPER", "DOS_FLOOD"]

    for att in attack_scenarios:
        test_df = simulate_scada_stream(
            duration_steps=400,
            attack_type=att,
            attack_start_step=150,
            attack_duration_steps=150,
            seed=999,
        )
        preds = bundle.predict_stream(test_df)
        attack_window_preds = preds[150:300]
        detected = [p for p in attack_window_preds if p.is_anomaly]
        detection_rate = (len(detected) / len(attack_window_preds)) * 100.0

        sample_pred = attack_window_preds[len(attack_window_preds) // 2]
        print(f"  Scenario: {att:14s} | Detection Rate: {detection_rate:5.1f}% | Vector: {sample_pred.detected_attack_vector:25s} | {sample_pred.mitre_ics_tactic}")

    if save_artifact:
        out_path = DEFAULT_SCADA_CONFIG.artifacts_dir / DEFAULT_SCADA_CONFIG.model_filename
        print(f"\n[Artifact] Saving detector bundle to: {out_path}")
        bundle.save(str(out_path))

    print("\n[SUCCESS] SCADA Cyber Detection pipeline completed successfully.")
    return bundle


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SCADA Cyber Detection CLI")
    args = parser.parse_args()
    run_pipeline(save_artifact=True)
