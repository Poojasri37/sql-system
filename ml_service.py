from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "outputs" / "models" / "isolation_forest.joblib"
METRICS_PATH = BASE_DIR / "outputs" / "reports" / "metrics.json"
MANIFEST_PATH = BASE_DIR / "model_manifest.json"


def _load_manifest() -> Dict[str, Any]:
    if MANIFEST_PATH.exists():
        with MANIFEST_PATH.open("r", encoding="utf-8") as f:
            return json.load(f)
    metrics = {}
    if METRICS_PATH.exists():
        with METRICS_PATH.open("r", encoding="utf-8") as f:
            metrics = json.load(f)
    return {
        "model_name": "IsolationForest SQL Anomaly Detector",
        "model_version": "1.0.0",
        "training_dataset": "synthetic_sql_logs.csv",
        "provenance": "Synthetic SQL log dataset created after workspace inspection because no SQL-specific dataset was present.",
        "training_timestamp": "2026-10-13T00:00:00Z",
        "expected_input_schema": [
            "user_id", "database_name", "query_type", "table_name", "privilege_level",
            "query_length", "rows_returned", "duration_ms", "bytes_transferred",
            "num_join_tables", "error_count", "is_successful", "after_hours", "query_frequency",
            "sensitive_table"
        ],
        "feature_names": [
            "user_id", "database_name", "query_type", "table_name", "privilege_level",
            "query_length", "rows_returned", "duration_ms", "bytes_transferred",
            "num_join_tables", "error_count", "is_successful", "session_hour", "day_of_week",
            "month", "after_hours", "query_frequency", "unusual_volume",
            "large_object_transfer", "high_frequency_user", "sensitive_access"
        ],
        "evaluation_metrics": metrics,
        "artifacts": {
            "model": str(MODEL_PATH),
            "metrics": str(METRICS_PATH),
        },
    }


ARTIFACT = joblib.load(MODEL_PATH)
MODEL: IsolationForest = ARTIFACT["model"]
PREPROCESSOR: ColumnTransformer = ARTIFACT["preprocessor"]
FEATURE_COLUMNS: List[str] = ARTIFACT["feature_columns"]
MODEL_MANIFEST = _load_manifest()


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _ensure_timestamp(value: Any) -> pd.Timestamp:
    if isinstance(value, pd.Timestamp):
        return value
    if value is None:
        return pd.Timestamp.utcnow()
    return pd.to_datetime(value)


def _build_feature_row(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    event = dict(raw_event)
    timestamp = _ensure_timestamp(event.get("timestamp"))
    event["timestamp"] = timestamp

    event.setdefault("user_id", "unknown_user")
    event.setdefault("database_name", "unknown_db")
    event.setdefault("query_type", "SELECT")
    event.setdefault("table_name", "unknown_table")
    event.setdefault("privilege_level", "read")
    event.setdefault("query_length", 0)
    event.setdefault("rows_returned", 0)
    event.setdefault("duration_ms", 0)
    event.setdefault("bytes_transferred", 0)
    event.setdefault("num_join_tables", 0)
    event.setdefault("error_count", 0)
    event.setdefault("is_successful", 1)
    event.setdefault("after_hours", 0)
    event.setdefault("query_frequency", 1)
    event.setdefault("sensitive_table", 0)

    event["session_hour"] = int(timestamp.hour)
    event["day_of_week"] = int(timestamp.dayofweek)
    event["month"] = int(timestamp.month)
    event["unusual_volume"] = int(_safe_float(event.get("rows_returned"), 0.0) > 0)
    event["large_object_transfer"] = int(_safe_float(event.get("bytes_transferred"), 0.0) > 0)
    event["high_frequency_user"] = int(_safe_float(event.get("query_frequency"), 1.0) > 0)
    event["late_night_access"] = int(event.get("after_hours", 0))
    event["sensitive_access"] = int(event.get("sensitive_table", 0))

    # Keep generated features aligned with training feature order.
    row: Dict[str, Any] = {}
    for name in FEATURE_COLUMNS:
        if name in event:
            row[name] = event[name]
        elif name == "session_hour":
            row[name] = event["session_hour"]
        elif name == "day_of_week":
            row[name] = event["day_of_week"]
        elif name == "month":
            row[name] = event["month"]
        elif name == "unusual_volume":
            row[name] = event["unusual_volume"]
        elif name == "large_object_transfer":
            row[name] = event["large_object_transfer"]
        elif name == "high_frequency_user":
            row[name] = event["high_frequency_user"]
        elif name == "sensitive_access":
            row[name] = event["sensitive_access"]
        else:
            row[name] = 0
    return row


def _classify_risk(score: float) -> str:
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def _explain_event(row: Dict[str, Any]) -> str:
    reasons: List[str] = []
    if row.get("after_hours") == 1:
        reasons.append("after-hours access")
    if row.get("sensitive_access") == 1:
        reasons.append("sensitive-table access")
    if row.get("unusual_volume") == 1:
        reasons.append("unusually large data volume")
    if row.get("large_object_transfer") == 1:
        reasons.append("large bytes transferred")
    if row.get("high_frequency_user") == 1:
        reasons.append("abnormal query frequency")
    if _safe_float(row.get("error_count"), 0.0) > 2:
        reasons.append("multiple query errors")
    if _safe_float(row.get("query_length"), 0.0) > 3000:
        reasons.append("very large query body")
    if _safe_float(row.get("rows_returned"), 0.0) > 100000:
        reasons.append("very high row count")
    if _safe_float(row.get("duration_ms"), 0.0) > 2000:
        reasons.append("extended query duration")
    if not reasons:
        return "No strong anomaly signature detected; low-confidence deviation."
    return "; ".join(reasons)


def predict_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    validation_errors = validate_event(raw_event)
    if validation_errors:
        raise ValueError("; ".join(validation_errors))

    row = _build_feature_row(raw_event)
    df = pd.DataFrame([row], columns=FEATURE_COLUMNS)
    transformed = PREPROCESSOR.transform(df)
    raw_prediction = MODEL.predict(transformed)[0]
    anomaly_score = float(-MODEL.score_samples(transformed)[0])
    risk_score = float(np.clip((anomaly_score - np.min([0.0, anomaly_score])) / (max(anomaly_score, 1.0) + 1e-8) * 100, 0, 100))
    risk_score = float(np.clip(risk_score, 0, 100))
    risk_level = _classify_risk(risk_score)
    explanation = _explain_event(row)
    return {
        "predicted_anomaly": int(raw_prediction == -1),
        "anomaly_label": "anomaly" if raw_prediction == -1 else "normal",
        "anomaly_score": anomaly_score,
        "risk_score": round(risk_score, 2),
        "risk_level": risk_level,
        "explanation": explanation,
        "source_record": row,
    }


def validate_event(raw_event: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    required = [
        "user_id", "database_name", "query_type", "table_name", "privilege_level",
        "query_length", "rows_returned", "duration_ms", "bytes_transferred",
        "num_join_tables", "error_count", "is_successful"
    ]
    for field in required:
        if field not in raw_event:
            errors.append(f"Missing required field: {field}")
    if "timestamp" not in raw_event:
        errors.append("Missing required field: timestamp")
    return errors


def get_model_manifest() -> Dict[str, Any]:
    return MODEL_MANIFEST
