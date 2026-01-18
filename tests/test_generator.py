"""Unit tests for SCADA physical plant simulation and attack injections."""

import pandas as pd
import pytest
from src.generator import simulate_scada_stream


def test_simulate_stream_nominal():
    df = simulate_scada_stream(duration_steps=200, attack_type="NONE", seed=42)
    assert len(df) == 200
    assert not df["is_attack"].any()
    assert (df["water_level_m"] > 0.0).all()
    assert (df["pressure_bar"] > 0.0).all()
    assert (df["modbus_packet_rate_hz"] > 0.0).all()


def test_simulate_stream_attack_modes():
    for att in ["FDI", "REPLAY", "VALVE_TAMPER", "DOS_FLOOD"]:
        df = simulate_scada_stream(
            duration_steps=100,
            attack_type=att,
            attack_start_step=30,
            attack_duration_steps=40,
            seed=100,
        )
        assert len(df) == 100
        attack_slice = df.iloc[30:70]
        assert attack_slice["is_attack"].all()
        assert (attack_slice["attack_type"] == att).all()
