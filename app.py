from __future__ import annotations

import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd
from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from ml_service import TRAINING_DATASET_PATH, get_model_manifest, predict_event

BASE_DIR = Path(__file__).resolve().parent
METRICS_PATH = BASE_DIR / "outputs" / "reports" / "metrics.json"
PREDICTIONS_PATH = BASE_DIR / "outputs" / "reports" / "predictions.csv"
USERS_DB_PATH = BASE_DIR / "users.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "sql-anomaly-dev-secret")
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "sql-anomaly-jwt-secret")

jwt = JWTManager(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri="memory://",
    default_limits=["30 per minute"],
)
bcrypt = Bcrypt(app)

def _get_user_hash(username: str) -> str | None:
    with sqlite3.connect(USERS_DB_PATH) as connection:
        row = connection.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    return row[0] if row else None


def _initialize_users() -> None:
    with sqlite3.connect(USERS_DB_PATH) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        for username, password in (("admin", "admin123"), ("analyst", "analyst123")):
            if connection.execute(
                "SELECT 1 FROM users WHERE username = ?",
                (username,),
            ).fetchone() is None:
                password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
                connection.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash),
                )


_initialize_users()


def _load_metrics() -> Dict[str, Any]:
    if not METRICS_PATH.exists():
        return {"status": "missing", "message": "metrics file not found"}
    with METRICS_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_alerts(limit: int = 10) -> List[Dict[str, Any]]:
    if not PREDICTIONS_PATH.exists():
        return []
    df = pd.read_csv(PREDICTIONS_PATH)
    if df.empty:
        return []
    df = df[df["predicted_anomaly"] == 1].sort_values("risk_score", ascending=False)
    return df.head(limit).to_dict(orient="records")


def _authenticated_user() -> str | None:
    username = session.get("username")
    return username if isinstance(username, str) else None


@app.route("/")
def index():
    if session.get("username"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        stored_hash = _get_user_hash(username)
        if stored_hash and bcrypt.check_password_hash(stored_hash, password):
            session["username"] = username
            return redirect(url_for("dashboard"))
        error = "Invalid username or password."
    return render_template("login.html", error=error, manifest=get_model_manifest())


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""
        if not re.fullmatch(r"[A-Za-z0-9_]{3,32}", username):
            error = "Use 3–32 letters, numbers, or underscores for your username."
        elif len(password) < 8:
            error = "Choose a password with at least 8 characters."
        elif password != confirm_password:
            error = "The passwords do not match."
        else:
            password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
            try:
                with sqlite3.connect(USERS_DB_PATH) as connection:
                    connection.execute(
                        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                        (username, password_hash),
                    )
            except sqlite3.IntegrityError:
                error = "That username is already registered."
            else:
                session["username"] = username
                return redirect(url_for("dashboard"))
    return render_template("register.html", error=error, manifest=get_model_manifest())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    username = _authenticated_user()
    if not username:
        return redirect(url_for("login"))
    metrics = _load_metrics()
    alerts = _load_alerts(10)
    return render_template(
        "dashboard.html",
        username=username,
        metrics=metrics,
        alerts=alerts,
        manifest=get_model_manifest(),
        active_page="dashboard",
    )


@app.route("/analysis")
def analysis():
    username = _authenticated_user()
    if not username:
        return redirect(url_for("login"))
    return render_template(
        "analysis.html",
        username=username,
        active_page="analysis",
    )


@app.route("/api/dataset/random")
def api_random_dataset_event():
    if not _authenticated_user():
        return jsonify({"error": "Please sign in to load a dataset record."}), 401
    if not TRAINING_DATASET_PATH.exists():
        return jsonify({"error": "The workspace SQL event dataset was not found."}), 404

    df = pd.read_csv(TRAINING_DATASET_PATH)
    if df.empty:
        return jsonify({"error": "The workspace SQL event dataset is empty."}), 404
    event = df.sample(n=1).iloc[0]
    timestamp = pd.to_datetime(event["timestamp"], errors="raise").strftime("%Y-%m-%dT%H:%M")
    return jsonify({
        "event_id": int(event["event_id"]),
        "timestamp": timestamp,
        "user_id": str(event["user_id"]),
        "database_name": str(event["database_name"]),
        "query_type": str(event["query_type"]),
        "table_name": str(event["table_name"]),
        "privilege_level": str(event["privilege_level"]),
        "query_length": int(event["query_length"]),
        "rows_returned": int(event["rows_returned"]),
        "duration_ms": int(event["duration_ms"]),
        "bytes_transferred": int(event["bytes_transferred"]),
        "num_join_tables": int(event["num_join_tables"]),
        "error_count": int(event["error_count"]),
        "is_successful": int(event["is_successful"]),
        "query_frequency": int(event["query_frequency"]),
        "sensitive_table": int(event["sensitive_table"]),
        "source": "synthetic_sql_logs.csv",
    })


@app.route("/alerts")
def alerts_page():
    username = _authenticated_user()
    if not username:
        return redirect(url_for("login"))
    return render_template(
        "alerts.html",
        username=username,
        alerts=_load_alerts(50),
        active_page="alerts",
    )


@app.route("/recommendations")
def recommendations():
    username = _authenticated_user()
    if not username:
        return redirect(url_for("login"))
    return render_template(
        "recommendations.html",
        username=username,
        active_page="recommendations",
    )


@app.route("/model")
def model_insights():
    username = _authenticated_user()
    if not username:
        return redirect(url_for("login"))
    return render_template(
        "model.html",
        username=username,
        metrics=_load_metrics(),
        manifest=get_model_manifest(),
        active_page="model",
    )


@app.route("/api/health")
def api_health():
    return jsonify({
        "status": "ok",
        "model": get_model_manifest()["model_name"],
        "version": get_model_manifest()["model_version"],
        "dataset": get_model_manifest()["training_dataset"],
    })


@app.route("/api/login", methods=["POST"])
def api_login():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    stored_hash = _get_user_hash(username)
    if not stored_hash or not bcrypt.check_password_hash(stored_hash, password):
        return jsonify({"error": "Invalid username or password."}), 401
    token = create_access_token(identity=username)
    return jsonify({"access_token": token, "token_type": "Bearer", "user": username})


@app.route("/api/session-token")
def api_session_token():
    username = _authenticated_user()
    if not username:
        return jsonify({"error": "Please sign in again to continue."}), 401
    return jsonify({"access_token": create_access_token(identity=username), "token_type": "Bearer"})


@app.route("/api/metrics")
def api_metrics():
    return jsonify(_load_metrics())


@app.route("/api/predict", methods=["POST"])
@jwt_required()
@limiter.limit("30/minute")
def api_predict():
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Request body must be valid JSON."}), 400
    try:
        result = predict_event(payload)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"user": get_jwt_identity(), **result})


@app.route("/api/recent-alerts")
@jwt_required()
def api_recent_alerts():
    return jsonify({"alerts": _load_alerts(10)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
