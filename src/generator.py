"""Physics-based SCADA water treatment plant telemetry and cyber-attack generator."""

from dataclasses import dataclass
from typing import Tuple, List
import numpy as np
import pandas as pd
from src.config import ScadaConfig, DEFAULT_SCADA_CONFIG


@dataclass
class ScadaSample:
    timestamp_sec: float
    water_level_m: float
    pump_inflow_lps: float
    valve_outflow_lps: float
    pressure_bar: float
    water_temp_c: float
    modbus_packet_rate_hz: float
    modbus_crc_errors: int
    is_attack: bool
    attack_type: str  # NONE, REPLAY, FDI, VALVE_TAMPER, DOS_FLOOD


def simulate_scada_stream(
    duration_steps: int = 1200,
    attack_type: str = "NONE",
    attack_start_step: int = 600,
    attack_duration_steps: int = 250,
    seed: int = 42,
    config: ScadaConfig = DEFAULT_SCADA_CONFIG,
) -> pd.DataFrame:
    """
    Simulates continuous differential state variables for a water treatment reservoir
    under PID level control, with optional industrial cyber-attack injections.
    """
    np.random.seed(seed)
    dt = config.sampling_rate_sec
    area = config.tank_area_sq_meters

    level = config.nominal_water_level_m
    integral_err = 0.0
    records: List[dict] = []

    # Historical buffer for replay attack
    replay_buffer: List[dict] = []

    for t in range(duration_steps):
        is_attack = False
        current_attack = "NONE"

        if attack_type != "NONE" and attack_start_step <= t < (attack_start_step + attack_duration_steps):
            is_attack = True
            current_attack = attack_type

        # Nominal demand outflow (varies smoothly)
        base_outflow = 50.0 + 15.0 * np.sin(2 * np.pi * t / 400.0) + np.random.normal(0, 1.5)
        base_outflow = np.clip(base_outflow, 10.0, config.max_outflow_rate_lps)

        # PID Controller for Inflow Pump
        error = config.nominal_water_level_m - level
        integral_err += error * dt
        kp = 35.0
        ki = 0.8
        pump_cmd = 50.0 + (kp * error) + (ki * integral_err)
        pump_inflow = float(np.clip(pump_cmd + np.random.normal(0, 1.2), 0.0, config.max_inflow_rate_lps))

        actual_outflow = base_outflow

        # Attack logic tampering
        if current_attack == "VALVE_TAMPER":
            # Attacker forces outlet valve wide open, ignoring PID balance
            actual_outflow = 115.0

        elif current_attack == "REPLAY":
            # Real-world Replay Attack: attacker overrides physical valve to 110 L/s drain
            # while streaming benign nominal sensor packets to HMI / SCADA
            actual_outflow = 110.0

        # Physical Mass Balance Differential Equation:
        # dh/dt = (Q_in - Q_out) / A (converted from L/s to m^3/s: divide by 1000)
        net_flow_m3ps = (pump_inflow - actual_outflow) / 1000.0
        level += (net_flow_m3ps / area) * dt
        level = float(np.clip(level, config.min_water_level_m, config.max_water_level_m))

        # Pipeline Hydrostatic + Dynamic Pressure (bar)
        # 1 meter water head ~ 0.0981 bar
        pressure = (level * 0.0981) + 3.7 + (pump_inflow * 0.005) + np.random.normal(0, 0.03)
        temp = 20.0 + 0.5 * np.sin(2 * np.pi * t / 600.0) + np.random.normal(0, 0.05)

        # Modbus protocol telemetry
        modbus_rate = float(np.random.poisson(10.0))
        crc_errs = int(np.random.binomial(1, 0.005))

        reported_level = level
        reported_inflow = pump_inflow
        reported_outflow = actual_outflow
        reported_pressure = pressure

        if current_attack == "FDI":
            # Stealth False Data Injection: ramp level bias +0.025m per step
            elapsed_attack = t - attack_start_step
            reported_level = level + (0.025 * elapsed_attack)

        elif current_attack == "REPLAY":
            if len(replay_buffer) > 30:
                replay_sample = replay_buffer[len(replay_buffer) - 30]
                # Attacker replays historical nominal telemetry for level and flows
                # but downstream physical pressure transducer measures actual hydrostatic drop
                reported_level = replay_sample["water_level_m"]
                reported_inflow = replay_sample["pump_inflow_lps"]
                reported_outflow = replay_sample["valve_outflow_lps"]
                reported_pressure = pressure

        elif current_attack == "DOS_FLOOD":
            modbus_rate = float(np.random.normal(165.0, 15.0))
            crc_errs = int(np.random.binomial(20, 0.35))

        record = {
            "timestamp_sec": float(t),
            "water_level_m": round(reported_level, 3),
            "pump_inflow_lps": round(reported_inflow, 2),
            "valve_outflow_lps": round(reported_outflow, 2),
            "pressure_bar": round(reported_pressure, 3),
            "water_temp_c": round(temp, 2),
            "modbus_packet_rate_hz": round(modbus_rate, 1),
            "modbus_crc_errors": crc_errs,
            "is_attack": is_attack,
            "attack_type": current_attack,
        }
        records.append(record)
        replay_buffer.append(record)

    return pd.DataFrame(records)
