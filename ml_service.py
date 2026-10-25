from __future__ import annotations

import json
import math
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
TRAINING_DATASET_PATH = BASE_DIR / "synthetic_sql_logs.csv"


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


def _load_training_reference() -> tuple[Dict[str, float], float, float]:
    if not TRAINING_DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Training data required for feature calibration was not found: {TRAINING_DATASET_PATH}"
        )

    training_data = pd.read_csv(TRAINING_DATASET_PATH)
    training_data["timestamp"] = pd.to_datetime(training_data["timestamp"], errors="raise")
    thresholds = {
        "query_length": float(training_data["query_length"].quantile(0.95)),
        "rows_returned": float(training_data["rows_returned"].quantile(0.95)),
        "bytes_transferred": float(training_data["bytes_transferred"].quantile(0.95)),
        "duration_ms": float(training_data["duration_ms"].quantile(0.95)),
        "query_frequency": float(training_data["query_frequency"].quantile(0.95)),
    }
    training_data["session_hour"] = training_data["timestamp"].dt.hour
    training_data["day_of_week"] = training_data["timestamp"].dt.dayofweek
    training_data["month"] = training_data["timestamp"].dt.month
    training_data["unusual_volume"] = (
        training_data["rows_returned"] > thresholds["rows_returned"]
    ).astype(int)
    training_data["large_object_transfer"] = (
        training_data["bytes_transferred"] > thresholds["bytes_transferred"]
    ).astype(int)
    training_data["high_frequency_user"] = (
        training_data["query_frequency"] > thresholds["query_frequency"]
    ).astype(int)
    training_data["sensitive_access"] = training_data["sensitive_table"].astype(int)

    features = training_data[FEATURE_COLUMNS]
    scores = MODEL.score_samples(PREPROCESSOR.transform(features))
    return thresholds, float(scores.min()), float(scores.max())


FEATURE_THRESHOLDS, REFERENCE_SCORE_MIN, REFERENCE_SCORE_MAX = _load_training_reference()


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _ensure_timestamp(value: Any) -> pd.Timestamp:
    if isinstance(value, pd.Timestamp):
        timestamp = value
    else:
        try:
            timestamp = pd.to_datetime(value, errors="raise")
        except (TypeError, ValueError) as exc:
            raise ValueError("Timestamp must be a valid date and time.") from exc
    if pd.isna(timestamp):
        raise ValueError("Timestamp must be a valid date and time.")
    return timestamp


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
    event.setdefault("after_hours", int(timestamp.hour < 7 or timestamp.hour >= 22))
    event.setdefault("query_frequency", 1)
    event.setdefault("sensitive_table", 0)

    event["session_hour"] = int(timestamp.hour)
    event["day_of_week"] = int(timestamp.dayofweek)
    event["month"] = int(timestamp.month)
    event["unusual_volume"] = int(
        _safe_float(event.get("rows_returned"), 0.0) > FEATURE_THRESHOLDS["rows_returned"]
    )
    event["large_object_transfer"] = int(
        _safe_float(event.get("bytes_transferred"), 0.0) > FEATURE_THRESHOLDS["bytes_transferred"]
    )
    event["high_frequency_user"] = int(
        _safe_float(event.get("query_frequency"), 0.0) > FEATURE_THRESHOLDS["query_frequency"]
    )
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
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def _risk_score(model_score: float) -> float:
    threshold = float(MODEL.offset_)
    low = min(REFERENCE_SCORE_MIN, threshold)
    high = max(REFERENCE_SCORE_MAX, threshold)
    if model_score < threshold:
        score = 70 + 30 * (threshold - model_score) / max(threshold - low, 1e-12)
    else:
        score = 70 * (high - model_score) / max(high - threshold, 1e-12)
    return float(np.clip(score, 0, 100))


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
    if _safe_float(row.get("query_length"), 0.0) > FEATURE_THRESHOLDS["query_length"]:
        reasons.append("very large query body")
    if row.get("unusual_volume") == 1:
        reasons.append("very high row count")
    if _safe_float(row.get("duration_ms"), 0.0) > FEATURE_THRESHOLDS["duration_ms"]:
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
    model_score = float(MODEL.score_samples(transformed)[0])
    anomaly_score = float(-model_score)
    risk_score = _risk_score(model_score)
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
        "num_join_tables", "error_count", "is_successful", "query_frequency",
        "sensitive_table"
    ]
    for field in required:
        if field not in raw_event:
            errors.append(f"Missing required field: {field}")
    if "timestamp" not in raw_event:
        errors.append("Missing required field: timestamp")
    elif raw_event["timestamp"] in (None, ""):
        errors.append("Timestamp is required.")
    else:
        try:
            _ensure_timestamp(raw_event["timestamp"])
        except ValueError as exc:
            errors.append(str(exc))

    text_fields = ["user_id", "database_name", "query_type", "table_name", "privilege_level"]
    for field in text_fields:
        if field in raw_event and not str(raw_event[field]).strip():
            errors.append(f"{field.replace('_', ' ').capitalize()} is required.")

    numeric_fields = [
        "query_length", "rows_returned", "duration_ms", "bytes_transferred",
        "num_join_tables", "error_count", "is_successful", "query_frequency",
        "after_hours", "sensitive_table",
    ]
    for field in numeric_fields:
        if field not in raw_event:
            continue
        try:
            value = float(raw_event[field])
        except (TypeError, ValueError):
            errors.append(f"{field.replace('_', ' ').capitalize()} must be a number.")
            continue
        if not math.isfinite(value) or value < 0:
            errors.append(f"{field.replace('_', ' ').capitalize()} must be a non-negative number.")
        elif field in {"is_successful", "after_hours", "sensitive_table"} and value not in (0, 1):
            errors.append(f"{field.replace('_', ' ').capitalize()} must be 0 or 1.")
    return errors


def get_model_manifest() -> Dict[str, Any]:
    return MODEL_MANIFEST
