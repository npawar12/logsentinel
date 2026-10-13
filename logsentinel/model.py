"""Unsupervised anomaly scoring with an Isolation Forest.

Rules catch patterns we already know about. The model catches "this looks different from
everything else" without us defining what different means.

Each row of the feature table is one (source IP, hour) bucket of activity.
"""
from __future__ import annotations

import pandas as pd
from sklearn.ensemble import IsolationForest

FEATURES = ["n_fail", "n_success", "n_users", "fail_ratio", "hour"]


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=["ip", "window"] + FEATURES)
    d = df.assign(
        window=df["timestamp"].dt.floor("h"),
        is_fail=df["event"].isin(["failure", "invalid_user"]).astype(int),
        is_success=(df["event"] == "success").astype(int),
    )
    feats = d.groupby(["ip", "window"]).agg(
        n_fail=("is_fail", "sum"),
        n_success=("is_success", "sum"),
        n_users=("user", "nunique"),
    ).reset_index()
    total = feats["n_fail"] + feats["n_success"]
    feats["fail_ratio"] = (feats["n_fail"] / total.where(total > 0, 1)).round(3)
    feats["hour"] = feats["window"].dt.hour
    return feats


def score(df: pd.DataFrame, contamination: float = 0.02, random_state: int = 42) -> pd.DataFrame:
    """Return the feature table with `anomaly_score` (higher = more anomalous) and `is_anomaly`."""
    feats = build_features(df)
    if len(feats) < 10:  # too little data to learn what "normal" looks like
        return feats.assign(anomaly_score=0.0, is_anomaly=False)
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=random_state)
    X = feats[FEATURES].astype(float)
    model.fit(X)
    # score_samples is higher for normal points, so negate it.
    feats["anomaly_score"] = (-model.score_samples(X)).round(4)
    feats["is_anomaly"] = model.predict(X) == -1
    return feats.sort_values("anomaly_score", ascending=False).reset_index(drop=True)
