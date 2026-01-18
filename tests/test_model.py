"""Unit tests for Isolation Forest & invariant rule bundle."""

import tempfile
from pathlib import Path
import pytest
from src.generator import simulate_scada_stream
from src.model import train_scada_detector, ScadaCyberAnomalyDetectorBundle


@pytest.fixture(scope="module")
def trained_bundle():
    nominal_df = simulate_scada_stream(duration_steps=600, attack_type="NONE", seed=42)
    bundle = train_scada_detector(nominal_df)
    return bundle


def test_bundle_nominal_evaluation(trained_bundle):
    test_df = simulate_scada_stream(duration_steps=100, attack_type="NONE", seed=99)
    preds = trained_bundle.predict_stream(test_df)
    anomalies = [p for p in preds if p.is_anomaly]
    # False positive rate should be below 5%
    assert len(anomalies) / len(preds) < 0.05


def test_bundle_dos_flood_detection(trained_bundle):
    test_df = simulate_scada_stream(
        duration_steps=80,
        attack_type="DOS_FLOOD",
        attack_start_step=20,
        attack_duration_steps=40,
        seed=10,
    )
    preds = trained_bundle.predict_stream(test_df)
    attack_preds = preds[20:60]
    detected = [p for p in attack_preds if p.is_anomaly]
    assert len(detected) / len(attack_preds) >= 0.90
    assert any(p.detected_attack_vector == "MODBUS_DOS_FLOOD" for p in detected)


def test_bundle_save_and_load(trained_bundle):
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "bundle.joblib"
        trained_bundle.save(str(path))
        loaded = ScadaCyberAnomalyDetectorBundle.load(str(path))
        assert loaded.mass_res_threshold == trained_bundle.mass_res_threshold
