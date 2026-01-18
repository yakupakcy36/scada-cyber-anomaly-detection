"""Integration tests for SCADA Cyber Anomaly FastAPI endpoints."""

import pytest
from fastapi.testclient import TestClient
from api.app import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["detector_loaded"] is True
    assert data["mass_res_threshold"] > 0


def test_evaluate_batch_endpoint(client):
    payload = {
        "telemetry": [
            {
                "timestamp_sec": 1.0,
                "water_level_m": 5.0,
                "pump_inflow_lps": 50.0,
                "valve_outflow_lps": 50.0,
                "pressure_bar": 4.44,
                "water_temp_c": 20.0,
                "modbus_packet_rate_hz": 10.0,
                "modbus_crc_errors": 0
            }
        ]
    }
    response = client.post("/evaluate/batch", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["alert_level"] in ["NOMINAL", "SUSPICIOUS"]


def test_simulate_attack_endpoint(client):
    payload = {
        "attack_type": "DOS_FLOOD",
        "duration_steps": 120,
        "attack_start_step": 30,
        "attack_duration_steps": 50,
        "seed": 42
    }
    response = client.post("/simulate/attack", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["attack_type"] == "DOS_FLOOD"
    assert data["attack_window_detection_rate_pct"] > 80.0
    assert "Denial of Service" in data["dominant_mitre_tactic"]
