"""Unit tests for feature extraction & physical invariants."""

import numpy as np
from src.generator import simulate_scada_stream
from src.features import ScadaFeatureExtractor


def test_feature_extraction_invariants():
    df = simulate_scada_stream(duration_steps=150, attack_type="NONE", seed=42)
    extractor = ScadaFeatureExtractor()
    X, y = extractor.extract_features(df)

    assert len(X) == 150
    assert "mass_balance_residual" in X.columns
    assert "hydrostatic_residual" in X.columns
    assert "dh_dt" in X.columns

    # Nominal mass balance residual must be small (< 0.005 m/s)
    assert X["mass_balance_residual"].max() < 0.005
    # Nominal hydrostatic residual must be small (< 0.15 bar)
    assert X["hydrostatic_residual"].max() < 0.15
    assert not X.isna().any().any()
